package jp.co.axio.masterMentsetSystem.model;

import java.util.Date;

public class VLoginInfoEntity {
    private String userId;

	private String companyCode;

	private String organizationCode;

	private String positionCode;

	private String userOrganizationHonmuFlag;

	private Date userOrganizationStartDate;

	private Date userOrganizationEndDate;

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId == null ? null : userId.trim();
	}

	public String getCompanyCode() {
		return companyCode;
	}

	public void setCompanyCode(String companyCode) {
		this.companyCode = companyCode == null ? null : companyCode.trim();
	}

	public String getOrganizationCode() {
		return organizationCode;
	}

	public void setOrganizationCode(String organizationCode) {
		this.organizationCode = organizationCode == null ? null : organizationCode.trim();
	}

	public String getPositionCode() {
		return positionCode;
	}

	public void setPositionCode(String positionCode) {
		this.positionCode = positionCode == null ? null : positionCode.trim();
	}

	public String getUserOrganizationHonmuFlag() {
		return userOrganizationHonmuFlag;
	}

	public void setUserOrganizationHonmuFlag(String userOrganizationHonmuFlag) {
		this.userOrganizationHonmuFlag = userOrganizationHonmuFlag == null ? null : userOrganizationHonmuFlag.trim();
	}

	/**
	* 本務フラグをBooleanに変換
	* @return
	*/
	public Boolean isHonmu() {

		return "1".equals(userOrganizationHonmuFlag) ? true : false;
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
}