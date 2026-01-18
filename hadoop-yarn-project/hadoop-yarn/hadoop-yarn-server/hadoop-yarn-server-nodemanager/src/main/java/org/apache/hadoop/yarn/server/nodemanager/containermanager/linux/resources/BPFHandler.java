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
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.yarn.server.nodemanager.containermanager.linux.privileged.PrivilegedOperation;
import org.apache.hadoop.yarn.server.nodemanager.containermanager.linux.privileged.PrivilegedOperationException;
import org.apache.hadoop.yarn.server.nodemanager.containermanager.linux.privileged.PrivilegedOperationExecutor;

/**
 * Wrapper around the 'bpftool'. Operations using PrivilegedOperation.
 * Mount bpf file system,
 * Create, delete, modify bpf maps,
 * Attach bpf program to tc.
 */
public class BPFHandler {
  private static final Logger LOG =
      LoggerFactory.getLogger(BPFHandler.class);
  private final Configuration conf;
  private final PrivilegedOperationExecutor privilegedOperationExecutor;

  private final String bpfMountPoint = "/sys/fs/bpf";
  private final String bpfPinFile;
  private final Integer KEY_SIZE = 1024;
  private final Integer MAX_ENTRIES = 1024;

  private String tmpDirPath;

  // TODO : key, value size 도 외부에서 받기
  private static final String FORMAT_CREATE_BPF_MAP =
      "map create %s[FILE] type TYPE key %d value %d entries 1024 name %s"; // 13
  private static final String FORMAT_DELETE_BPF_MAP =
      "rm %s/$s"; // 2
  private static final String FORMAT_ADD_ENTRY_BPF_MAP =
      "map update %s key hex %s value hex %s any"; // 10
  private static final String FORMAT_DELETE_ENTRY_BPF_MAP =
      "map delete %s key %s"; // map delete MAP key DATA // 5
  private static final String FORMAT_ATTACH_NET_PROGRAM =
      "net attach tcx_ingress name tc_prog dev lo";

  private static final String TMP_FILE_PREFIX = "tmp";
  private static final String TMP_FILE_SUFFIX = ".cmds";

  BPFHandler(PrivilegedOperationExecutor privilegedOperationExecutor, Configuration conf,
      String bpfPinFile) {
    this.conf = conf;
    this.privilegedOperationExecutor = privilegedOperationExecutor;
    this.bpfPinFile = bpfPinFile;
  }

  public void bootstrap() throws ResourceHandlerException {
    String tmpDirBase = conf.get("hadoop.tmp.dir");
    if (tmpDirBase == null) {
      throw new ResourceHandlerException("hadoop.tmp.dir not set!");
    }
    this.tmpDirPath = tmpDirBase + "/bpftool-cmd";

    File tmpDir = new File(tmpDirPath);
    if (!(tmpDir.exists() || tmpDir.mkdirs())) {
      LOG.warn("Unable to create directory: " + tmpDirPath);
      throw new ResourceHandlerException("Unable to create directory: " +
          tmpDirPath);
    }
  }

  // cgroup을 위한 BPF맵 생성한다고 메서드 이름 지은 뒤
  // 맵 이름만 받고 나머지 파라미터들은 적절하게 정하자.
  // 예: 값은 1024개 키,값 hexadecimal...
  // containerId 를 키에 저장하기 위해선 키의 길이는 64가 되어야 함. see; @ContainerId
  public void createBpfHashMap(String mapName, Integer keySize, Integer valueSize)
      throws ResourceHandlerException {
    String opString = String.format(FORMAT_CREATE_BPF_MAP, bpfPinFile, keySize, valueSize, mapName);
    PrivilegedOperation op = commitCommandToTempFile(opString, PrivilegedOperation.OperationType.BPFTOOL_CREATE_MAP);
    try {
      LOG.info("Creating BPF HashMap : {}", mapName);
      privilegedOperationExecutor.executePrivilegedOperation(op, false);
    } catch (PrivilegedOperationException e) {
      LOG.warn("Failed to create BPF Hashmap.");
      throw new ResourceHandlerException("Failed to create BPF Hashmap.", e);
    }
  }

  public void deleteBpfHashMap(String mapName)
      throws ResourceHandlerException {
    PrivilegedOperation op = commitCommandToTempFile("rm" + bpfMountPoint + "/" + mapName, PrivilegedOperation.OperationType.BPFTOOL_DELETE_MAP);
    try {
      LOG.info("Deleting BPF HashMap : {}", mapName);
      privilegedOperationExecutor.executePrivilegedOperation(op, false);
    } catch (PrivilegedOperationException e) {
      LOG.warn("Failed to delete BPF Hashmap.");
      throw new ResourceHandlerException("Failed to delete BPF Hashmap.", e);
    }
  }

  public void addToBpfHashMap(String mapName, String key, String value)
      throws ResourceHandlerException, PrivilegedOperationException {
    // 'bpftool map update' gets key, value argument as ascii(10) and stores hexadecimal form.
    String asciiKey = stringToAscii(key);
    String asciiValue = stringToAscii(value);
    String opString = String.format(FORMAT_ADD_ENTRY_BPF_MAP, mapName, asciiKey, asciiValue);
    PrivilegedOperation op = commitCommandToTempFile(opString, PrivilegedOperation.OperationType.BPFTOOL_ADD_ENTRY);
    privilegedOperationExecutor.executePrivilegedOperation(op, false);
  }

  public void deleteToBpfHashMap(String mapName, String key)
      throws ResourceHandlerException, PrivilegedOperationException {
    String opString = String.format(FORMAT_DELETE_ENTRY_BPF_MAP, mapName, key);
    PrivilegedOperation op = commitCommandToTempFile(opString, PrivilegedOperation.OperationType.BPFTOOL_DELETE_ENTRY);
    privilegedOperationExecutor.executePrivilegedOperation(op, false);
  }

  public void loadBpfProgram(String programPath)
    throws ResourceHandlerException, PrivilegedOperationException {
    PrivilegedOperation op = commitCommandToTempFile(opString, PrivilegedOperation.OperationType.BPFTOOL_DELETE_ENTRY);
    privilegedOperationExecutor.executePrivilegedOperation(op, false);
  }

  private PrivilegedOperation commitCommandToTempFile(String command, PrivilegedOperation.OperationType optype)
      throws ResourceHandlerException {
    try {
      File bpftoolCmds = File.createTempFile(TMP_FILE_PREFIX, TMP_FILE_SUFFIX, new
          File(tmpDirPath));

      try (
          Writer writer = new OutputStreamWriter(new FileOutputStream(bpftoolCmds),
              StandardCharsets.UTF_8);
          PrintWriter printWriter = new PrintWriter(writer)) {
          printWriter.println(command);
      }

      PrivilegedOperation operation = new PrivilegedOperation(optype);
      operation.appendArgs(bpftoolCmds.getAbsolutePath());

      return operation;
    } catch (IOException e) {
      LOG.warn("Failed to create or write to temporary file in dir: " +
          tmpDirPath);
      throw new ResourceHandlerException(
          "Failed to create or write to temporary file in dir: "
              + tmpDirPath);
    }
  }

  private String stringToAscii(String input) {
    String text = "Hello BPF!";

    StringBuilder asciiResult = new StringBuilder();

    for (int i = 0; i < input.length(); i++) {
      char character = input.charAt(i);
      int asciiValue = (int) character;

      asciiResult.append(asciiValue);

      if (i < input.length() - 1) {
        asciiResult.append(" ");
      }
    }

    return asciiResult.toString();
  }
}
