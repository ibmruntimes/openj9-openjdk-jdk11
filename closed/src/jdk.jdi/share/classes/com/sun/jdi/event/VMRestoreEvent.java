/*[INCLUDE-IF CRIU_SUPPORT]*/
/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2023, 2024 All Rights Reserved
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
package com.sun.jdi.event;

import com.sun.jdi.ThreadReference;
import com.sun.jdi.VirtualMachine;

/**
 * Notification of when the VM is restored from a checkpoint. Similar to
 * VMStartEvent this occurs before application code has run, including any
 * application hooks for the restore event.
 * The event is generated even if not explicitly requested.
 *
 * @see VMStartEvent
 * @see VMDeathEvent
 * @see EventQueue
 * @see VirtualMachine
 */
public interface VMRestoreEvent extends Event {

    /**
     * Returns the thread which is restoring the VM from a checkpoint.
     *
     * @return a {@link ThreadReference} representing the restore thread
     * on the target VM.
     */
    public ThreadReference thread();
}
