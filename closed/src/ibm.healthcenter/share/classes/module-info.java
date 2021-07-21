/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2021, 2021 All Rights Reserved
 * ===========================================================================
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
 * ===========================================================================
 */

/**
 * Provides the agent that supports IBM Monitoring and Diagnostic Tools - Health Center.
 */
module ibm.healthcenter {
  requires java.logging;
  requires java.management;
  requires java.naming;
  requires java.prefs;
  requires java.rmi;
  requires openj9.traceformat;
  exports com.ibm.java.diagnostics.healthcenter.agent.mbean;
  exports com.ibm.java.diagnostics.healthcenter.api;
  exports com.ibm.java.diagnostics.healthcenter.api.classes;
  exports com.ibm.java.diagnostics.healthcenter.api.cpu;
  exports com.ibm.java.diagnostics.healthcenter.api.environment;
  exports com.ibm.java.diagnostics.healthcenter.api.factory;
  exports com.ibm.java.diagnostics.healthcenter.api.gc;
  exports com.ibm.java.diagnostics.healthcenter.api.io;
  exports com.ibm.java.diagnostics.healthcenter.api.locking;
  exports com.ibm.java.diagnostics.healthcenter.api.methodtrace;
  exports com.ibm.java.diagnostics.healthcenter.api.nativememory;
  exports com.ibm.java.diagnostics.healthcenter.api.profiling;
  exports com.ibm.java.diagnostics.healthcenter.api.threads;
  exports com.ibm.java.diagnostics.healthcenter.api.vmcontrol;
}
