package jp.co.axio.masterMentsetSystem.controller;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import lombok.Getter;
import lombok.Setter;

/**
 * @author tonoi
 *
 */
@Setter
@Getter
public class OrganizationInfo {

	/**
	 * 所属会社コード
	 */
	private String companyCode;
	/**
	 * 所属組織コード
	 */
	private String organizationCode;
	/**
	 * 役職コード
	 */
	private String positionCode;
	/**
	 * 本務フラグ true:本務,false：兼務
	 */
	private Boolean isHonmu;

	@Override
	public String toString() {
		return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
	}
}
