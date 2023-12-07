package jp.co.axio.masterMentsetSystem.controller;

import java.io.Serializable;
import java.util.List;

import javax.validation.groups.Default;

import jp.co.axio.masterMentsetSystem.dto.AuthOrgCodeListDto;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AuthOrgCodeListForm implements Serializable {

	/**
	 * 組織コード一覧フォーム
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

	//モーダル格納エリア　メイン画面とダブルしないように別ネームする
	public String dailogCallFrom;
	public String dailogCallParameter;

	/** 呼び出し元画面からのパラメータ： callReturn */
	public String callReturn;

	/** チェックしたコード */
	public String checkedCodes;

	/** 検索条件　有効基準日（yyyy/MM/dd形式） */
//	@AxioDateFormat(groups = {SearchGroup.class})
	public String searchStartDateYmd;

	/** 検索条件　適用終了日（未使用）（yyyy/MM/dd形式） */
//	@AxioDateFormat(groups = {SearchGroup.class})
	public String searchEndDateYmd;

	/** 検索条件　会社コード */
	public String searchCompanyCode;

	/** 検索条件　組織コード */
	public String searchDepartmentCode;

	/** 検索条件　組織名称 */
	public String searchDepartmentName;

	/** 検索結果一覧 */
	public List<AuthOrgCodeListDto> searchResultList;

	/** Error message */
	public String errMessage;
}
