package jp.co.axio.masterMentsetSystem.model;

import java.util.Date;

public class VUserListEntity {
    private String state;

    private String userId;

    private String employmentKbn;

    private String employmentKbnName;

    private String userNameJp;

    private String userNameEn;

    private String usernameForSearch;

    private String companyCode;

    private String companyName;

    private String organizationCode;

    private String organizationName;

    private String positionCode;

    private String positionName;

    private Date userStartDate;

    private Date userEndDate;

    private String userInvalidFlag;

    private Date userOrganizationStartDate;

    private Date userOrganizationEndDate;

    private String userOrganizationInvalidFlag;

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state == null ? null : state.trim();
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId == null ? null : userId.trim();
    }

    public String getEmploymentKbn() {
        return employmentKbn;
    }

    public void setEmploymentKbn(String employmentKbn) {
        this.employmentKbn = employmentKbn == null ? null : employmentKbn.trim();
    }

    public String getEmploymentKbnName() {
        return employmentKbnName;
    }

    public void setEmploymentKbnName(String employmentKbnName) {
        this.employmentKbnName = employmentKbnName == null ? null : employmentKbnName.trim();
    }

    public String getUserNameJp() {
        return userNameJp;
    }

    public void setUserNameJp(String userNameJp) {
        this.userNameJp = userNameJp == null ? null : userNameJp.trim();
    }

    public String getUserNameEn() {
        return userNameEn;
    }

    public void setUserNameEn(String userNameEn) {
        this.userNameEn = userNameEn == null ? null : userNameEn.trim();
    }

    public String getUsernameForSearch() {
        return usernameForSearch;
    }

    public void setUsernameForSearch(String usernameForSearch) {
        this.usernameForSearch = usernameForSearch == null ? null : usernameForSearch.trim();
    }

    public String getCompanyCode() {
        return companyCode;
    }

    public void setCompanyCode(String companyCode) {
        this.companyCode = companyCode == null ? null : companyCode.trim();
    }

    public String getCompanyName() {
        return companyName;
    }

    public void setCompanyName(String companyName) {
        this.companyName = companyName == null ? null : companyName.trim();
    }

    public String getOrganizationCode() {
        return organizationCode;
    }

    public void setOrganizationCode(String organizationCode) {
        this.organizationCode = organizationCode == null ? null : organizationCode.trim();
    }

    public String getOrganizationName() {
        return organizationName;
    }

    public void setOrganizationName(String organizationName) {
        this.organizationName = organizationName == null ? null : organizationName.trim();
    }

    public String getPositionCode() {
        return positionCode;
    }

    public void setPositionCode(String positionCode) {
        this.positionCode = positionCode == null ? null : positionCode.trim();
    }

    public String getPositionName() {
        return positionName;
    }

    public void setPositionName(String positionName) {
        this.positionName = positionName == null ? null : positionName.trim();
    }

    public Date getUserStartDate() {
        return userStartDate;
    }

    public void setUserStartDate(Date userStartDate) {
        this.userStartDate = userStartDate;
    }

    public Date getUserEndDate() {
        return userEndDate;
    }

    public void setUserEndDate(Date userEndDate) {
        this.userEndDate = userEndDate;
    }

    public String getUserInvalidFlag() {
        return userInvalidFlag;
    }

    public void setUserInvalidFlag(String userInvalidFlag) {
        this.userInvalidFlag = userInvalidFlag == null ? null : userInvalidFlag.trim();
    }

    public Date getUserOrganizationStartDate() {
        return userOrganizationStartDate;
    }

    public void setUserOrganizationStartDate(Date userOrganizationStartDate) {
        this.userOrganizationStartDate = userOrganizationStartDate;
    }

    public Date getUserOrganizationEndDate() {
        return userOrganizationEndDate;
    }

    public void setUserOrganizationEndDate(Date userOrganizationEndDate) {
        this.userOrganizationEndDate = userOrganizationEndDate;
    }

    public String getUserOrganizationInvalidFlag() {
        return userOrganizationInvalidFlag;
    }

    public void setUserOrganizationInvalidFlag(String userOrganizationInvalidFlag) {
        this.userOrganizationInvalidFlag = userOrganizationInvalidFlag == null ? null : userOrganizationInvalidFlag.trim();
    }
}