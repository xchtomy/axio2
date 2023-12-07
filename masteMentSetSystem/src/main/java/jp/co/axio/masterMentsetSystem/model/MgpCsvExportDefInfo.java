package jp.co.axio.masterMentsetSystem.model;

import java.util.Date;

public class MgpCsvExportDefInfo {
    private Integer sqlNo;

    private String systemId;

    private String sqlRegisterName;

    private String validFlag;

    private String fileSavePath;

    private String fileName;

    private String fileClass;

    private String fileNamingClass;

    private String strCode;

    private String delimiterClass;

    private String fileCodeFormatClass;

    private String separationDefClass;

    private String fileHeaderInfoClass;

    private String sqlOutTableName;

    private String sqlOutData;

    private String sqlColumnDef;

    private String sqlWhereDef;

    private String registerId;

    private Date registTs;

    private String updaterId;

    private Date updateTs;

    private Integer versionNumber;

    public Integer getSqlNo() {
        return sqlNo;
    }

    public void setSqlNo(Integer sqlNo) {
        this.sqlNo = sqlNo;
    }

    public String getSystemId() {
        return systemId;
    }

    public void setSystemId(String systemId) {
        this.systemId = systemId == null ? null : systemId.trim();
    }

    public String getSqlRegisterName() {
        return sqlRegisterName;
    }

    public void setSqlRegisterName(String sqlRegisterName) {
        this.sqlRegisterName = sqlRegisterName == null ? null : sqlRegisterName.trim();
    }

    public String getValidFlag() {
        return validFlag;
    }

    public void setValidFlag(String validFlag) {
        this.validFlag = validFlag == null ? null : validFlag.trim();
    }

    public String getFileSavePath() {
        return fileSavePath;
    }

    public void setFileSavePath(String fileSavePath) {
        this.fileSavePath = fileSavePath == null ? null : fileSavePath.trim();
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName == null ? null : fileName.trim();
    }

    public String getFileClass() {
        return fileClass;
    }

    public void setFileClass(String fileClass) {
        this.fileClass = fileClass == null ? null : fileClass.trim();
    }

    public String getFileNamingClass() {
        return fileNamingClass;
    }

    public void setFileNamingClass(String fileNamingClass) {
        this.fileNamingClass = fileNamingClass == null ? null : fileNamingClass.trim();
    }

    public String getStrCode() {
        return strCode;
    }

    public void setStrCode(String strCode) {
        this.strCode = strCode == null ? null : strCode.trim();
    }

    public String getDelimiterClass() {
        return delimiterClass;
    }

    public void setDelimiterClass(String delimiterClass) {
        this.delimiterClass = delimiterClass == null ? null : delimiterClass.trim();
    }

    public String getFileCodeFormatClass() {
        return fileCodeFormatClass;
    }

    public void setFileCodeFormatClass(String fileCodeFormatClass) {
        this.fileCodeFormatClass = fileCodeFormatClass == null ? null : fileCodeFormatClass.trim();
    }

    public String getSeparationDefClass() {
        return separationDefClass;
    }

    public void setSeparationDefClass(String separationDefClass) {
        this.separationDefClass = separationDefClass == null ? null : separationDefClass.trim();
    }

    public String getFileHeaderInfoClass() {
        return fileHeaderInfoClass;
    }

    public void setFileHeaderInfoClass(String fileHeaderInfoClass) {
        this.fileHeaderInfoClass = fileHeaderInfoClass == null ? null : fileHeaderInfoClass.trim();
    }

    public String getSqlOutTableName() {
        return sqlOutTableName;
    }

    public void setSqlOutTableName(String sqlOutTableName) {
        this.sqlOutTableName = sqlOutTableName == null ? null : sqlOutTableName.trim();
    }

    public String getSqlOutData() {
        return sqlOutData;
    }

    public void setSqlOutData(String sqlOutData) {
        this.sqlOutData = sqlOutData == null ? null : sqlOutData.trim();
    }

    public String getSqlColumnDef() {
        return sqlColumnDef;
    }

    public void setSqlColumnDef(String sqlColumnDef) {
        this.sqlColumnDef = sqlColumnDef == null ? null : sqlColumnDef.trim();
    }

    public String getSqlWhereDef() {
        return sqlWhereDef;
    }

    public void setSqlWhereDef(String sqlWhereDef) {
        this.sqlWhereDef = sqlWhereDef == null ? null : sqlWhereDef.trim();
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