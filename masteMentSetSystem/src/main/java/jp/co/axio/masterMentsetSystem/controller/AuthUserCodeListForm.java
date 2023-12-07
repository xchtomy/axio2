package jp.co.axio.masterMentsetSystem.controller;

import java.io.Serializable;
import java.util.List;

import javax.validation.groups.Default;

import jp.co.axio.masterMentsetSystem.dto.AuthUserCodeListDto;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AuthUserCodeListForm implements Serializable {

	/**
	 * ユーザーID一覧フォーム
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

	/** 検索条件　有効基準日（yyyy/MM/dd形式） 未使用 */
//	@AxioDateFormat(groups = {SearchGroup.class})
	public String searchStartDateYmd;

	/** 検索条件　未使用（yyyy/MM/dd形式） */
//	@AxioDateFormat(groups = {SearchGroup.class})
	public String searchEndDateYmd;

	/** 検索条件　会社コード　未使用 */
	public String searchCompanyCode;

	/** 検索条件　ユーザーID */
	public String searchUserCode;

	/** 検索条件　ユーザー氏名 */
	public String searchUserName;

	/** 検索結果一覧 */
	public List<AuthUserCodeListDto> searchResultList;

	/** Error message */
	public String errMessage;
}
