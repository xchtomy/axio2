package jp.co.axio.masterMentsetSystem.controller;

import java.io.Serializable;
import java.util.List;

import javax.validation.groups.Default;

import jp.co.axio.masterMentsetSystem.common.AxioDateFormat;
import jp.co.axio.masterMentsetSystem.controller.AuthRuleSetForm.SaveGroup;
import jp.co.axio.masterMentsetSystem.dto.AuthPosCodeListDto;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AuthPosCodeListForm implements Serializable {

	/**
	 * 役職コード一覧フォーム
	 */
	private static final long serialVersionUID = 1L;

	/** 検索ボタングループ */
	interface SearchGroup extends Default{}

	/** 確定ボタングループ */
	interface OkGroup extends Default{}

	/** キャンセルボタングループ */
	interface CancelGroup extends Default{}

	/** 呼び出し元画面からのパラメータ： callForm */
	public String callForm;

	/** 呼び出し元画面からのパラメータ： callParameter */
	public String callParameter;

	/** 呼び出し元画面からのパラメータ： callReturn */
	public String callReturn;

	/** チェックしたコード */
	public String checkedCodes;

	/** 検索条件　有効基準日（yyyy/MM/dd形式） */
//	@AxioDateFormat(groups = {SearchGroup.class})
	public String searchStartDateYmd;

	/** 検索条件　未使用（yyyy/MM/dd形式） */
//	@AxioDateFormat(groups = {SearchGroup.class})
	public String searchEndDateYmd;

	/** 検索条件　会社コード */
	public String searchCompanyCode;

	/** 検索条件　役職コード */
	public String searchPositionCode;

	/** 検索条件　役職名称 */
	public String searchPositionName;

	/** 検索結果一覧 */
	public List<AuthPosCodeListDto> searchResultList;

	/** Error message */
	public String errMessage;
}
