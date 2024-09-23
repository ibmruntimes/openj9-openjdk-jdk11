/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2024, 2024 All Rights Reserved
 * ===========================================================================
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * IBM designates this particular file as subject to the "Classpath" exception
 * as provided by IBM in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, see <http://www.gnu.org/licenses/>.
 *
 * ===========================================================================
 */

#include "criuhelpers.h"

#if defined(J9VM_OPT_CRAC_SUPPORT)

#include "java.h"
#include <ctype.h>
#include <sys/wait.h>

/**
 * Get the value of a command line option in the array of command line arguments.
 * @param[in] optionName The name of the command line option to search for
 * @param[in] argc The number of command line arguments
 * @param[in] argv The array of command line arguments
 * @param[out] error A pointer to an integer for the error code
 * @return A pointer to the value of the command line option if found, NULL otherwise
 */
static const char *
getCommandLineOptionValue(const char *optionName, int argc, char **argv, int *error)
{
    const char *value = NULL;
    int i = 0;
    size_t optionNameLength = strlen(optionName);
    *error = -1;
    for (i = argc - 1; i >= 0; i--) {
        const char *arg = argv[i];
        if (0 == strncmp(arg, optionName, optionNameLength)) {
            const char *equals = arg + optionNameLength;
            if (('=' == *equals) || ('\0' == *equals)) {
                *error = 0;
                value = equals;
                if ('=' == *value) {
                    value += 1;
                }
                if ('\0' == *value) {
                    value = NULL;
                }
                break;
            }
        }
    }
    return value;
}

/**
 * Get the checkpoint directory from command line options.
 * @param[in] argc The number of command line arguments
 * @param[in] argv The array of command line arguments
 * @param[in/out] error A pointer to an integer for the error code
 * @return A pointer to the checkpoint directory if found, NULL otherwise
 */
static const char *
getCheckpointDirectory(int argc, char **argv, int *error)
{
    const char *checkpointDirectory = NULL;
    const char *checkpointDirectoryPropertyValue = getCommandLineOptionValue("-XX:CRaCRestoreFrom", argc, argv, error);
    if (0 == *error) {
        if (NULL != checkpointDirectoryPropertyValue) {
            checkpointDirectory = checkpointDirectoryPropertyValue;
        } else {
            JLI_ReportErrorMessage("The value of the command line option -XX:CRaCRestoreFrom was not found.");
            *error = -2;
        }
    }
    return checkpointDirectory;
}

/**
 * Get the log level specified in the command line arguments.
 * Valid log levels are from 0 to 4, inclusive; the default is 2.
 * @param[in] argc The number of command line arguments
 * @param[in] argv The array of command line arguments
 * @param[in/out] error A pointer to an integer for the error code
 * @return The log level integer if successful, default of 2 otherwise
 */
static int
getLogLevel(int argc, char **argv, int *error)
{
    int logLevelValue = 2; /* default */
    const char *logLevelPropertyValue = getCommandLineOptionValue("-Dopenj9.internal.criu.logLevel", argc, argv, error);
    if (0 == *error) {
        const char *c = logLevelPropertyValue;
        if (NULL == c) {
            goto done;
        }
        for (; '\0' != *c; c++) {
            if (!isdigit(*c)) {
                goto setLogLevelOptionValueNotValidError;
            }
        }
        logLevelValue = atoi(logLevelPropertyValue);
        if ((0 <= logLevelValue) && (logLevelValue <= 4)) {
            goto done;
        } else {
            goto setLogLevelOptionValueNotValidError;
        }
    } else if (-1 == *error) {
        goto done;
    }
setLogLevelOptionValueNotValidError:
    JLI_ReportErrorMessage(
            "The option '-Dopenj9.internal.criu.logLevel=%s' is not valid.",
            logLevelPropertyValue);
    *error = -2;
done:
    return logLevelValue;
}

/**
 * Check if the unprivileged mode is specified in the command line arguments.
 * @param[in] argc The number of command line arguments
 * @param[in] argv The array of command line arguments
 * @param[in/out] error A pointer to an integer for the error code
 * @return true if the unprivileged mode option is specified in the command line arguments, false otherwise
 */
static jboolean
isUnprivilegedModeOn(int argc, char **argv, int *error)
{
    jboolean isUnprivilegedModeOn = JNI_FALSE;
    const char *unprivilegedModePropertyValue = getCommandLineOptionValue("-Dopenj9.internal.criu.unprivilegedMode", argc, argv, error);
    if (0 == *error) {
        if (NULL == unprivilegedModePropertyValue) {
            isUnprivilegedModeOn = JNI_TRUE;
        } else {
            JLI_ReportErrorMessage(
                    "The option '-Dopenj9.internal.criu.unprivilegedMode=%s' does not accept a value.",
                    unprivilegedModePropertyValue);
            *error = -2;
        }
    }
    return isUnprivilegedModeOn;
}

/**
 * Get the log file specified in the command line arguments.
 * @param[in] argc The number of command line arguments
 * @param[in] argv The array of command line arguments
 * @param[in/out] error A pointer to an integer for the error code
 * @return A pointer to the log file string if successful, NULL otherwise
 */
static const char *
getLogFile(int argc, char **argv, int *error)
{
    const char *logFile = NULL;
    const char *logFilePropertyValue = getCommandLineOptionValue("-Dopenj9.internal.criu.logFile", argc, argv, error);
    if (0 == *error) {
        if (NULL != logFilePropertyValue) {
            logFile = logFilePropertyValue;
        } else {
            JLI_ReportErrorMessage("The option -Dopenj9.internal.criu.logFile requires a value.");
            *error = -2;
        }
    }
    return logFile;
}

/**
 * Restore the system state from a checkpoint using the CRIU tool.
 * @param[in] checkpointDirectory The directory containing the checkpoint data
 * @param[in] logLevel The log level for CRIU logging
 * @param[in] unprivilegedModeOn Indicates whether the unprivileged mode option is on
 * @param[in] logFile The log file option for CRIU
 * @return 0 if the execution of the 'criu restore' command succeeds, -1 otherwise
 */
static int
restoreFromCheckpoint(const char *checkpointDirectory, int logLevel, jboolean unprivilegedModeOn, const char *logFile)
{
    int length = -1;
    char logLevelOption[4] = { 0 };
    char *logFileOption = NULL;
    int argc = 0;
    const char *argv[9] = { NULL };
    argv[argc++] = "criu";
    argv[argc++] = "restore";
    argv[argc++] = "-D";
    argv[argc++] = checkpointDirectory;
    /* The log level is a single digit. */
    snprintf(logLevelOption, sizeof(logLevelOption), "-v%d", logLevel);
    argv[argc++] = logLevelOption;
    argv[argc++] = "--shell-job";
    if (unprivilegedModeOn) {
        argv[argc++] = "--unprivileged";
    }
    if (NULL != logFile) {
        length = strlen(logFile) + sizeof("--log-file=%s") - 1;
        logFileOption = (char *)JLI_MemAlloc(length + 1);
        if (NULL == logFileOption) {
            JLI_ReportErrorMessage("Failed to allocate memory for option '--log-file=%s'.", logFile);
            goto fail;
        }
        if (snprintf(logFileOption, length + 1, "--log-file=%s", logFile) < 0) {
            JLI_ReportErrorMessage("Failed to format option '--log-file=%s'.", logFile);
            goto fail;
        }
        argv[argc++] = logFileOption;
    }
    argv[argc] = NULL;
    execvp(argv[0], (char * const *)argv);
    /* If execvp returns, there was an error. */
fail:
    if (NULL != logFileOption) {
        JLI_MemFree((void *)logFileOption);
    }
    return -1;
}

/**
 * Handle the restoration of the system state from a checkpoint.
 * @param[in] argc The number of command line arguments
 * @param[in] argv The array of command line arguments
 */
void
handleCRaCRestore(int argc, char **argv)
{
    const char *checkpointDirectory = NULL;
    int error = 0;
    int parentProcessExitStatus = EXIT_SUCCESS;
    pid_t childProcessPid = 0;
    int logLevel = 0;
    int childProcessExitStatus = EXIT_SUCCESS;
    jboolean unprivilegedModeOn = JNI_FALSE;
    const char *logFile = NULL;
    int childProcessPidStatus = 0;
    int childProcessPidExitStatus = 0;
    checkpointDirectory = getCheckpointDirectory(argc, argv, &error);
    if (-1 == error) {
        /* Option -XX:CRaCRestoreFrom not specified. */
        return;
    }
    if (-2 == error) {
        JLI_ReportErrorMessage("Failed to get the CRIU checkpoint directory.");
        parentProcessExitStatus = EXIT_FAILURE;
        goto doneParentProcess;
    }
    /*
     * The if block will be invoked by the child process,
     * and the else block will be invoked by the parent process.
     */
    childProcessPid = fork();
    if (0 == childProcessPid) {
        logLevel = getLogLevel(argc, argv, &error);
        if (-2 == error) {
            JLI_ReportErrorMessage("Failed to get the CRIU log level.");
            childProcessExitStatus = EXIT_FAILURE;
            goto doneChildProcess;
        }
        unprivilegedModeOn = isUnprivilegedModeOn(argc, argv, &error);
        if (-2 == error) {
            JLI_ReportErrorMessage("Failed to get the CRIU unprivileged mode.");
            childProcessExitStatus = EXIT_FAILURE;
            goto doneChildProcess;
        }
        logFile = getLogFile(argc, argv, &error);
        if (-2 == error) {
            JLI_ReportErrorMessage("Failed to get the CRIU log file.");
            childProcessExitStatus = EXIT_FAILURE;
            goto doneChildProcess;
        }
        childProcessExitStatus = restoreFromCheckpoint(checkpointDirectory, logLevel, unprivilegedModeOn, logFile);
doneChildProcess:
        exit(childProcessExitStatus);
    } else {
        waitpid(childProcessPid, &childProcessPidStatus, 0);
        if (WIFEXITED(childProcessPidStatus)) {
            childProcessPidExitStatus = WEXITSTATUS(childProcessPidStatus);
            if (EXIT_SUCCESS == childProcessPidExitStatus) {
                JLI_ReportMessage("Completed restore with -XX:CRaCRestoreFrom=PATH.");
            } else {
                JLI_ReportErrorMessage("Failed to restore from checkpoint, error=%d.", childProcessPidExitStatus);
                parentProcessExitStatus = EXIT_FAILURE;
            }
        } else {
            JLI_ReportErrorMessage("The CRIU restore child process failed.");
            parentProcessExitStatus = EXIT_FAILURE;
        }
    }
doneParentProcess:
    exit(parentProcessExitStatus);
}
#endif /* defined(J9VM_OPT_CRAC_SUPPORT) */
