package jp.co.axio.masterMentsetSystem.controller;

import java.io.Serializable;
import java.util.List;

import jp.co.axio.masterMentsetSystem.dto.RuleInfoListDto;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AuthRuleListForm implements Serializable {

	/**
	 * ルール一覧フォーム
	 */
	private static final long serialVersionUID = 1L;

	//モーダル画面呼び出すパラメータ　
	public String callFrom;
	public String callParameter;

	//モーダル格納エリア　メイン画面とダブルしないように別ネームする
	public String dailogCallFrom;
	public String dailogCallParameter;

	/** ルールID　*/
	public String dailogRuleId;

	/** ルール名（概要） */
	public String dailogRuleName;

	/** ルール備考 */
	public String dailogRuleNote;

	/** ルール検索の有効基準日 /YYYY/MM/DD */
	public String dailogStartDate;

	/** ルール検索　未使用 */
	public String dailogEndDate;

	/** 検索結果一覧 */
	public List<RuleInfoListDto> listRuleItems;

	/** チェックボックス選択値*/
	public List<String> listCheck;

	/** Error message */
	public String dailogErrMessage;

	/** checked ruleId */
	public String checkRuleId;
}
