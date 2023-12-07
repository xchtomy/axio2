package jp.co.axio.masterMentsetSystem.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * 権限管理ルール条件設定Dto
 *
 * @author JCBC
 */
@Setter
@Getter
public class RuleConditionSetDto {

    /** ルールID */
	public String ruleId;

	/** ルール名 */
	public String ruleName;

	/** ルール概要 */
	public String note;

	/** ルール適用開始日 */
	public String startDate;

	/** ルール適用終了日 */
	public String endDate;

}
