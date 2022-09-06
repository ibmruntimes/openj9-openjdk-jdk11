/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2019, 2022 All Rights Reserved
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

package requires;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Callable;

public class OpenJ9PropsExt implements Callable<Map<String, String>> {

    @Override
    public Map<String, String> call() {

        Map<String, String> map = new HashMap<>();
        try {
            map.put("vm.bits", vmBits());
            map.put("vm.graal.enabled", "false");
            map.put("vm.hasJFR", "false");
            map.put("vm.musl", "false");
        }
        catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        } 
        return map;
    }

    /**
     * @return VM bitness, the value of the "sun.arch.data.model" property.
     */
    protected String vmBits() throws Exception {
        String dataModel = System.getProperty("sun.arch.data.model");
        if (dataModel != null) {
            return dataModel;
        } else {
            throw new Exception("Can't get 'sun.arch.data.model' property");
        }
    }
}

