package jp.co.axio.masterMentsetSystem.model;

import java.util.Date;

public class MOrganizationEntity extends MOrganizationEntityKey {
    private Date startDate;

    private Date endDate;

    private String invalidFlag;

    private String organizationNameEn;

    private String organizationNameJp;

    private String locationCode;

    private String locationNameEn;

    private String locationNameJp;

    private String organizationDispOrder;

    private String organizationCodeTop;

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

    public String getOrganizationNameEn() {
        return organizationNameEn;
    }

    public void setOrganizationNameEn(String organizationNameEn) {
        this.organizationNameEn = organizationNameEn == null ? null : organizationNameEn.trim();
    }

    public String getOrganizationNameJp() {
        return organizationNameJp;
    }

    public void setOrganizationNameJp(String organizationNameJp) {
        this.organizationNameJp = organizationNameJp == null ? null : organizationNameJp.trim();
    }

    public String getLocationCode() {
        return locationCode;
    }

    public void setLocationCode(String locationCode) {
        this.locationCode = locationCode == null ? null : locationCode.trim();
    }

    public String getLocationNameEn() {
        return locationNameEn;
    }

    public void setLocationNameEn(String locationNameEn) {
        this.locationNameEn = locationNameEn == null ? null : locationNameEn.trim();
    }

    public String getLocationNameJp() {
        return locationNameJp;
    }

    public void setLocationNameJp(String locationNameJp) {
        this.locationNameJp = locationNameJp == null ? null : locationNameJp.trim();
    }

    public String getOrganizationDispOrder() {
        return organizationDispOrder;
    }

    public void setOrganizationDispOrder(String organizationDispOrder) {
        this.organizationDispOrder = organizationDispOrder == null ? null : organizationDispOrder.trim();
    }

    public String getOrganizationCodeTop() {
        return organizationCodeTop;
    }

    public void setOrganizationCodeTop(String organizationCodeTop) {
        this.organizationCodeTop = organizationCodeTop == null ? null : organizationCodeTop.trim();
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