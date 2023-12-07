package jp.co.axio.masterMentsetSystem.model;

import java.util.Date;

public class OutputScopeMst {
    private Integer outputScopeNo;

    private String outputScopeName;

    private String outputScopeTable;

    private String registerId;

    private Date registTs;

    private String updaterId;

    private Date updateTs;

    private Integer versionNumber;

    public Integer getOutputScopeNo() {
        return outputScopeNo;
    }

    public void setOutputScopeNo(Integer outputScopeNo) {
        this.outputScopeNo = outputScopeNo;
    }

    public String getOutputScopeName() {
        return outputScopeName;
    }

    public void setOutputScopeName(String outputScopeName) {
        this.outputScopeName = outputScopeName == null ? null : outputScopeName.trim();
    }

    public String getOutputScopeTable() {
        return outputScopeTable;
    }

    public void setOutputScopeTable(String outputScopeTable) {
        this.outputScopeTable = outputScopeTable == null ? null : outputScopeTable.trim();
    }

    public String getRegisterId() {
        return registerId;
    }

    public void setRegisterId(String registerId) {
        this.registerId = registerId == null ? null : registerId.trim();
    }

    public Date getRegistTs() {
        return registTs;
    }

    public void setRegistTs(Date registTs) {
        this.registTs = registTs;
    }

    public String getUpdaterId() {
        return updaterId;
    }

    public void setUpdaterId(String updaterId) {
        this.updaterId = updaterId == null ? null : updaterId.trim();
    }

    public Date getUpdateTs() {
        return updateTs;
    }

    public void setUpdateTs(Date updateTs) {
        this.updateTs = updateTs;
    }

    public Integer getVersionNumber() {
        return versionNumber;
    }

    public void setVersionNumber(Integer versionNumber) {
        this.versionNumber = versionNumber;
    }
}