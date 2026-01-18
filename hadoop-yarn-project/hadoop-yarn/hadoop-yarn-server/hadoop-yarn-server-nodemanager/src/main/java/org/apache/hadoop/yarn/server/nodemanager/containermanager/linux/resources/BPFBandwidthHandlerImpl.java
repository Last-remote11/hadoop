/*
 * *
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements. See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership. The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License. You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 * /
 */

package org.apache.hadoop.yarn.server.nodemanager.containermanager.linux.resources;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.yarn.api.records.ContainerId;
import org.apache.hadoop.yarn.server.nodemanager.containermanager.container.Container;
import org.apache.hadoop.yarn.server.nodemanager.containermanager.linux.privileged.PrivilegedOperation;
import org.apache.hadoop.yarn.server.nodemanager.containermanager.linux.privileged.PrivilegedOperationExecutor;

/**
 * Handler class to handle the outbound bandwidth using BPF. Since NET_CLS
 * controller disappeared in Cgroup V2, use BPF_PROG_TYPE_CGROUP_SKB type
 * BPF program to limit network outbound bandwidth of Cgroup.
 */

@InterfaceAudience.Private
@InterfaceStability.Unstable
public class BPFBandwidthHandlerImpl
    extends AbstractBandwidthHandler {

  private static final Logger LOG =
       LoggerFactory.getLogger(BPFBandwidthHandlerImpl.class);

  public BPFBandwidthHandlerImpl(PrivilegedOperationExecutor
      privilegedOperationExecutor, CGroupsHandler cGroupsHandler) {
    super(privilegedOperationExecutor, cGroupsHandler);
  }

  /**
   * Pre-start hook for 'outbound-bandwidth' resource.
   * @param container Container being launched
   * @return privileged operations for some cgroups/tc operations.
   * @throws ResourceHandlerException
   */
  @Override
  public List<PrivilegedOperation> preStart(Container container)
      throws ResourceHandlerException {
    String containerIdStr = container.getContainerId().toString();

    cGroupsHandler.createCGroup(CGroupsHandler.CGroupController
            .MISC,
        containerIdStr);

    //Now create a privileged operation in order to update the tasks file with
    //the pid of the running container process (root of process tree). This can
    //only be done at the time of launching the container, in a privileged
    //executable.
    String tasksFile = cGroupsHandler.getPathForCGroupTasks(
        CGroupsHandler.CGroupController.MISC, containerIdStr);
    String opArg = PrivilegedOperation.CGROUP_ARG_PREFIX + tasksFile;
    List<PrivilegedOperation> ops = new ArrayList<>();

    ops.add(new PrivilegedOperation(
        PrivilegedOperation.OperationType.ADD_PID_TO_CGROUP, opArg));

    String cgroupPath = cGroupsHandler.getPathForCGroup(
        CGroupsHandler.CGroupController.MISC, containerIdStr);
    ArrayList<String> bpfCmd = new ArrayList<>();
    bpfCmd.add(cgroupPath);
    bpfCmd.add(String.valueOf(containerBandwidthMbit));
    ops.add(new PrivilegedOperation(
        PrivilegedOperation.OperationType.RUN_BPF_BANDWIDTH, bpfCmd));

    return ops;
  }

  @Override
  public List<PrivilegedOperation> reacquireContainer(ContainerId containerId)
      throws ResourceHandlerException {
    String containerIdStr = containerId.toString();

    LOG.debug("Attempting to reacquire classId for container: {}",
        containerIdStr);

    return null;
  }

  /**
   * Returns total bytes sent per container to be used for metrics tracking
   * purposes.
   * @return a map of containerId to bytes sent
   * @throws ResourceHandlerException
   */
  public Map<ContainerId, Integer> getBytesSentPerContainer()
      throws ResourceHandlerException {
    Map<ContainerId, Integer> containerIdStats = new HashMap<>();
    LOG.warn("not implemented yet");
    return containerIdStats;
  }

  /**
   * Cleanup operations once container is completed - deletes cgroup
   * @param containerId of the container that was completed.
   * @return null
   * @throws ResourceHandlerException
   */
  @Override
  public List<PrivilegedOperation> postComplete(ContainerId containerId)
      throws ResourceHandlerException {
    LOG.info("postComplete for container: " + containerId.toString());

    // when delete cgroup, bpf programs that attached cgroup also deleted.
    cGroupsHandler.deleteCGroup(CGroupsHandler.CGroupController.MISC,
        containerId.toString());

    return null;
  }

  @Override
  public List<PrivilegedOperation> teardown()
      throws ResourceHandlerException {
    LOG.debug("teardown(): Nothing to do");

    return null;
  }

  @Override
  public String toString() {
    return BPFBandwidthHandlerImpl.class.getName();
  }

  @Override public CGroupsHandler.CGroupController getCgroupController() {
    return CGroupsHandler.CGroupController.MISC;
  }

  @Override
  public void additionalBootstrap() {
    // do nothing
  }
}
