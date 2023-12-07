package jp.co.axio.masterMentsetSystem.controller;

import java.io.Serializable;
import java.util.List;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import javax.validation.groups.Default;

import jp.co.axio.masterMentsetSystem.dto.RuleConditionGroupDto;
import jp.co.axio.masterMentsetSystem.dto.RuleConditionItemDto;
import jp.co.axio.masterMentsetSystem.dto.RuleConditionOptDto;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AuthRuleSetForm extends accessForm implements Serializable {

	/**
	 * ルール条件設定フォーム
	 */
	private static final long serialVersionUID = 1L;

	// ルール保存ボタングループ
	interface SaveGroup extends Default{}

	// ルール削除ボタングループ
	interface DeleteGroup extends Default{}

	// 一覧反映ボタングループ
	interface ReflectionGroup extends Default{}

	/** 検索フラグ １： ルール検索押下より値取得された場合*/
	public String searchFlg;

	/** ルール編集フラグ　１：ルール条件テキストエリアの値が変更ある場合 */
	public String editFlg;

	/** ルール条件変更フラグ 　１：テキストボックスの値、ルール条件一覧、及びグループ一覧が変更ある場合*/
	public String changedFlg;

	/** CallBack　function name */
	public String reflectFunction;

	/** ダイヤログから選択された値 */
	public String paramVal;

	/** ルールID　*/
	@NotBlank(groups = {DeleteGroup.class})
	public String ruleId;

	/** ルール名（概要） */
	@NotBlank(groups = {SaveGroup.class})
	@Size(min = 1, max = 100, groups = {SaveGroup.class})
	public String ruleName;

	/** ルール備考 */
	@Size(max = 1000, groups = {SaveGroup.class})
	public String ruleNote;

	/** ルール適用開始日 /YYYY/MM/DD */
//	@AxioDateFormat(groups = {SaveGroup.class})
	@NotBlank(groups = {SaveGroup.class})
	public String startDate;

	/** ルール適用終了日 */
//	@AxioDateFormat(groups = {SaveGroup.class})
	@NotBlank(groups = {SaveGroup.class})
	public String endDate;

	/** ルール条件セレクト：値 */
	public String ruleSelectOpt;
	public String currentOptValue;
	public String currentOptKbn;
	public String currentOptNo;

	/** ルール条件セレクト：選択リスト */
	public List<RuleConditionOptDto> ruleSelectList;

	/** ルール条件値：　会社 */
	public String companyCode;

	/** ルール条件値：　雇用区分 */
	public String employmentCode;

	/** ルール条件値：　組織 */
	public String organizationCode;

	/** ルール条件値：　役職 */
	public String positionCode;

	/** 個別ユーザー値：　付与 */
	public String userCode;

	/** 個別ユーザー値：　除外 */
	public String userExtCode;

	/** Error message */
	public String errMessage;

	/** 設定済ルール条件リスト */
	public List<RuleConditionItemDto> ruleConditionList;

	/** ルール条件適用済グループリスト */
	public List<RuleConditionGroupDto> ruleGroupList;

	/** ユーザー個別付与のフラグ */
	public String userSetFlag;
}
