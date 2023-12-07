package jp.co.axio.masterMentsetSystem.controller;

import java.io.Serializable;
import java.util.List;

import javax.validation.groups.Default;

import jp.co.axio.masterMentsetSystem.dto.AuthComCodeListDto;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AuthComCodeListForm implements Serializable {

	/**
	 * 会社コード一覧フォーム
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

	/** 検索条件　会社コード */
	public String searchCompanyCode;

	/** 検索条件　会社名称 */
	public String searchCompanyName;

	/** 検索結果一覧 */
	public List<AuthComCodeListDto> searchResultList;

	/** Error message */
	public String errMessage;
}
