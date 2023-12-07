package jp.co.axio.masterMentsetSystem.controller;

import java.io.Serializable;
import java.util.List;

import javax.validation.groups.Default;

import jp.co.axio.masterMentsetSystem.dto.AuthEmpCodeListDto;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AuthEmpCodeListForm implements Serializable {

	/**
	 * 雇用区分コード一覧フォーム
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

	/** 検索条件　雇用区分コード */
	public String searchEmploymentCode;

	/** 検索条件　雇用区分名称 */
	public String searchEmploymentName;

	/** 検索結果一覧 */
	public List<AuthEmpCodeListDto> searchResultList;

	/** Error message */
	public String errMessage;
}
