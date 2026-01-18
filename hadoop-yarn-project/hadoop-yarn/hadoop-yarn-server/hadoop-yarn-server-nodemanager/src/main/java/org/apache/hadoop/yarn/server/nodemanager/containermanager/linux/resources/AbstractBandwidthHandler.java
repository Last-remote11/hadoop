package org.apache.hadoop.yarn.server.nodemanager.containermanager.linux.resources;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.yarn.conf.YarnConfiguration;
import org.apache.hadoop.yarn.server.nodemanager.containermanager.container.Container;
import org.apache.hadoop.yarn.server.nodemanager.containermanager.linux.privileged.PrivilegedOperation;
import org.apache.hadoop.yarn.server.nodemanager.containermanager.linux.privileged.PrivilegedOperationExecutor;

public abstract class AbstractBandwidthHandler
    implements OutboundBandwidthResourceHandler {
  protected static final Logger LOG =
      LoggerFactory.getLogger(AbstractBandwidthHandler.class);
  //In the absence of 'scheduling' support, we'll 'infer' the guaranteed
  //outbound bandwidth for each container based on this number. This will
  //likely go away once we add support on the RM for this resource type.
  protected static final int MAX_CONTAINER_COUNT = 50;

  protected final PrivilegedOperationExecutor privilegedOperationExecutor;
  protected final CGroupsHandler cGroupsHandler;

  protected Configuration conf;
  protected String device;
  protected boolean strictMode;
  protected int containerBandwidthMbit;
  protected int rootBandwidthMbit;
  protected int yarnBandwidthMbit;

  public AbstractBandwidthHandler(PrivilegedOperationExecutor
          privilegedOperationExecutor, CGroupsHandler cGroupsHandler) {
    this.privilegedOperationExecutor = privilegedOperationExecutor;
    this.cGroupsHandler = cGroupsHandler; // v2 는 cgroupV2Handler 가 생성자에 들어올 것이다.
  }

  /**
   * Bootstrapping 'outbound-bandwidth' resource handler -
   * cgroup V1 : mounts net_cls
   * cgroup V2 : do nothing.
   * controller and bootstraps a bandwidth shaping hierarchy
   * @param configuration yarn configuration in use
   * @return (potentially empty) list of privileged operations to execute.
   * @throws ResourceHandlerException
   */
  @Override
  public List<PrivilegedOperation> bootstrap(Configuration configuration)
      throws ResourceHandlerException {
    conf = configuration;
    //We'll do this inline for the time being - since this is a one time
    //operation. At some point, LCE code can be refactored to batch mount
    //operations across multiple controllers - cpu, net_cls, blkio etc
    cGroupsHandler
        .initializeCGroupController(getCgroupController());
    device = conf.get(YarnConfiguration.NM_NETWORK_RESOURCE_INTERFACE,
        YarnConfiguration.DEFAULT_NM_NETWORK_RESOURCE_INTERFACE);
    strictMode = configuration.getBoolean(YarnConfiguration
        .NM_LINUX_CONTAINER_CGROUPS_STRICT_RESOURCE_USAGE, YarnConfiguration
        .DEFAULT_NM_LINUX_CONTAINER_CGROUPS_STRICT_RESOURCE_USAGE);
    rootBandwidthMbit = conf.getInt(YarnConfiguration
        .NM_NETWORK_RESOURCE_OUTBOUND_BANDWIDTH_MBIT, YarnConfiguration
        .DEFAULT_NM_NETWORK_RESOURCE_OUTBOUND_BANDWIDTH_MBIT);
    yarnBandwidthMbit = conf.getInt(YarnConfiguration
        .NM_NETWORK_RESOURCE_OUTBOUND_BANDWIDTH_YARN_MBIT, rootBandwidthMbit);
    containerBandwidthMbit = (int) Math.ceil((double) yarnBandwidthMbit /
        MAX_CONTAINER_COUNT);

    StringBuilder logLine = new StringBuilder("strict mode is set to :")
        .append(strictMode).append(System.lineSeparator());

    if (strictMode) {
      logLine.append("container bandwidth will be capped to soft limit.")
          .append(System.lineSeparator());
    } else {
      logLine.append(
              "containers will be allowed to use spare YARN bandwidth.")
          .append(System.lineSeparator());
    }

    logLine
        .append("containerBandwidthMbit soft limit (in mbit/sec) is set to : ")
        .append(containerBandwidthMbit);

    LOG.info(logLine.toString());
    additionalBootstrap();

    return null;
  }

  @Override
  public List<PrivilegedOperation> updateContainer(Container container)
      throws ResourceHandlerException {
    return null;
  }

  @Override
  public List<PrivilegedOperation> teardown()
      throws ResourceHandlerException {
    LOG.debug("teardown(): Nothing to do");

    return null;
  }

  abstract public CGroupsHandler.CGroupController getCgroupController();

  abstract public void additionalBootstrap() throws ResourceHandlerException;
}
