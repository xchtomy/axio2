package jp.co.axio.masterMentsetSystem.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * 権限管理ルールグループ関連Dto
 *
 * @author JCBC
 */
@Setter
@Getter
public class RuleConditionGroupDto {

	public String ruleId;

	public String groupId;

	public String groupNameJP;

	public String groupNameEn;

	public String startDate;

	public String endDate;

	public String note;

	public boolean delFlg;

}
