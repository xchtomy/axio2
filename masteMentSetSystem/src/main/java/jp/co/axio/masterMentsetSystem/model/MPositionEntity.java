package jp.co.axio.masterMentsetSystem.model;

import java.util.Date;

public class MPositionEntity extends MPositionEntityKey {
    private Date startDate;

    private Date endDate;

    private String invalidFlag;

    private String positionNameEn;

    private String positionNameJp;

    private String registerId;

    private Date registTs;

    private String updaterId;

    private Date updateTs;

    public Date getStartDate() {
        return startDate;
    }

    public void setStartDate(Date startDate) {
        this.startDate = startDate;
    }

    public Date getEndDate() {
        return endDate;
    }

    public void setEndDate(Date endDate) {
        this.endDate = endDate;
    }

    public String getInvalidFlag() {
        return invalidFlag;
    }

    public void setInvalidFlag(String invalidFlag) {
        this.invalidFlag = invalidFlag == null ? null : invalidFlag.trim();
    }

    public String getPositionNameEn() {
        return positionNameEn;
    }

    public void setPositionNameEn(String positionNameEn) {
        this.positionNameEn = positionNameEn == null ? null : positionNameEn.trim();
    }

    public String getPositionNameJp() {
        return positionNameJp;
    }

    public void setPositionNameJp(String positionNameJp) {
        this.positionNameJp = positionNameJp == null ? null : positionNameJp.trim();
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
}