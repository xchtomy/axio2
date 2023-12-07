package jp.co.axio.masterMentsetSystem.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * 権限管理ルール条件設定済項目Dto
 *
 * @author JCBC
 */
@Setter
@Getter
public class RuleConditionItemDto {

	/** ルールID */
	public String ruleId;

	/** ルール条件番号 */
	public String ruleDetailNo;

	/** ルール 付与条件:会社 */
	public String ruleSetCompany;

	/** ルール除外条件:会社 */
	public String ruleExtCompany;

	/** ルール 付与条件:雇用区分 */
	public String ruleSetEmployment;

	/** ルール 除外条件:雇用区分 */
	public String ruleExtEmployment;

	/** ルール 付与条件:組織 */
	public String ruleSetOrganization;

	/** ルール 除外条件:組織 */
	public String ruleExtOrganization;

	/** ルール 付与条件:役職 */
	public String ruleSetPosition;

	/** ルール 除外条件:役職 */
	public String ruleExtPosition;

}
