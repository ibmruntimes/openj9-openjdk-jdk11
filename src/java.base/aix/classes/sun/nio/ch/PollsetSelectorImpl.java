/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2025, 2025 All Rights Reserved
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
package sun.nio.ch;

import java.io.IOException;
import java.nio.channels.*;
import java.nio.channels.spi.*;
import java.util.*;
import java.util.function.Consumer;
import jdk.internal.misc.*;

/**
 * An implementation of Selector for AIX 5.3+ kernels that uses
 * the pollset event notification facility.
 */
class PollsetSelectorImpl
    extends SelectorImpl
{
    // File descriptors used for interrupt
    protected int fd0;
    protected int fd1;

    // The poll object
    PollsetArrayWrapper pollWrapper;

    // maps file descriptor to selection key, synchronize on selector
    private Map<Integer, SelectionKeyImpl> fdToKey;

    // True if this Selector has been closed
    private boolean closed = false;

    // pending updates, queued by putEventOps
    private final Object updateLock = new Object();
    private final Deque<SelectionKeyImpl> updateKeys = new ArrayDeque<>();

    // Lock for interrupt triggering and clearing
    private Object interruptLock = new Object();
    private boolean interruptTriggered = false;

    /**
     * Package private constructor called by factory method in
     * the abstract superclass Selector.
     */
    PollsetSelectorImpl(SelectorProvider sp) throws IOException {
        super(sp);
        try {
            long pipeFds = IOUtil.makePipe(false);
            fd0 = (int) (pipeFds >>> 32);
            fd1 = (int) pipeFds;
        } catch (IOException ioe) {
            throw ioe;
        }

        pollWrapper = new PollsetArrayWrapper();
        pollWrapper.initInterrupt(fd0, fd1);
        fdToKey = new HashMap<>();
    }

    /*
     * Selects a set of keys whose corresponding channels are ready for I/O
     * operations.
     */
    protected int doSelect(Consumer<SelectionKey> action, long timeout)
        throws IOException
    {
        if (closed)
            throw new ClosedSelectorException();
        processDeregisterQueue();
        try {
            begin();
                pollWrapper.poll(timeout);

        } finally {
            end();
        }
        processDeregisterQueue();
        int numKeysUpdated = updateSelectedKeys();
        if (pollWrapper.getReventOps(0) != 0) {
            synchronized (interruptLock) {
                IOUtil.drain(fd0);
                interruptTriggered = false;
            }
        }
        return numKeysUpdated;
    }


    /**
     * Update the keys whose fd's have been selected by the pollset.
     * Add the ready keys to the ready queue.
     */
    private int updateSelectedKeys() {
        int entries = pollWrapper.updated;
        int numKeysUpdated = 0;
        for (int i=0; i<entries; i++) {
            int nextFD = pollWrapper.getDescriptor(i);
            SelectionKeyImpl ski = (SelectionKeyImpl) fdToKey.get(
                new Integer(nextFD));
            // ski is null in the case of an interrupt
            if (ski != null) {
                int rOps = pollWrapper.getEventOps(i);
                if (selectedKeySet().contains(ski)) {
                    if (((SelChImpl) ski.channel()).translateAndSetReadyOps(rOps, ski)) {
                        numKeysUpdated++;
                    }
                } else {
                    ((SelChImpl) ski.channel()).translateAndSetReadyOps(rOps, ski);
                    if ((ski.nioReadyOps() & ski.nioInterestOps()) != 0) {
                        selectedKeySet().add(ski);
                        numKeysUpdated++;
                    }
                }
            }
        }
        return numKeysUpdated;
    }

    protected void implClose() throws IOException {
        if (!closed) {
            closed = true;
            FileDispatcherImpl.closeIntFD(fd0);
            FileDispatcherImpl.closeIntFD(fd1);
            if (pollWrapper != null) {

                pollWrapper.release(fd0);
                pollWrapper.closePollsetFD();
                pollWrapper = null;
                setSelectedKeySet(null);

                // Deregister channels
                Iterator<SelectionKey> i = keySet().iterator();
                while (i.hasNext()) {
                    SelectionKeyImpl ski = (SelectionKeyImpl)i.next();
                    deregister(ski);
                    SelectableChannel selch = ski.channel();
                    if (!selch.isOpen() && !selch.isRegistered())
                    ((SelChImpl)selch).kill();
                    i.remove();
                }
            }
            fd0 = -1;
            fd1 = -1;
        }
    }


    protected void implRegister(SelectionKeyImpl ski) {
        int fd = IOUtil.fdVal(((SelChImpl) ski.channel()).getFD());
        fdToKey.put(new Integer(fd), ski);
        pollWrapper.add(fd);
        keySet().add(ski);
    }

    protected void implDereg(SelectionKeyImpl ski) throws IOException {
        assert (ski.getIndex() >= 0);
        int fd = ((SelChImpl) ski.channel()).getFDVal();
        fdToKey.remove(new Integer(fd));
        pollWrapper.release(fd);
        ski.setIndex(-1);
        keySet().remove(ski);
        selectedKeySet().remove(ski);
        deregister((AbstractSelectionKey)ski);
        SelectableChannel selch = ski.channel();
        if (!selch.isOpen() && !selch.isRegistered())
            ((SelChImpl)selch).kill();
    }

    @Override
    public void setEventOps(SelectionKeyImpl ski) {
        // Adding this method for compilation issue
    }

    public void putEventOps(SelectionKeyImpl sk, int ops) {
        int fd = IOUtil.fdVal(((SelChImpl) sk.channel()).getFD());
        pollWrapper.setInterest(fd, ops);
    }

    /*
     * Causes the Earlier selection operation that has not yet returned to return
     * immediately
     */
    public Selector wakeup() {
        synchronized (interruptLock) {
            if (!interruptTriggered) {
                pollWrapper.interrupt();
                interruptTriggered = true;
            }
        }
        return this;
    }

    static {
        IOUtil.load();
    }

}
