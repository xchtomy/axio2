package jp.co.axio.masterMentsetSystem.controller;

import java.io.Serializable;
import java.util.List;

import jp.co.axio.masterMentsetSystem.dto.AuthGroupListDto;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AuthGroupListForm implements Serializable {

	/**
	 * グループ一覧フォーム
	 */
	private static final long serialVersionUID = 1L;

	//モーダル画面呼び出すパラメータ　
	public String callFrom;
	public String callParameter;

	//モーダル格納エリア　メイン画面とダブルしないように別ネームする
	public String dailogCallFrom;
	public String dailogCallParameter;

	/** グループID　*/
	public String dailogGroupId;

	/** グループ名（英語） */
	public String dailogGroupNameEn;

	/** グループ名（日本語） */
	public String dailogGroupNameJp;

	/** グループ備考 */
	public String dailogGroupNote;

	/** グループ検索の有効基準日 /YYYY/MM/DD */
	public String dailogStartDate;

	/** グループ検索　未使用 */
	public String dailogEndDate;

	/** 検索結果一覧 */
	public List<AuthGroupListDto> listGroupItems;

	/** チェックボックス選択値*/
	public List<String> listCheck;

	/** Error message */
	public String dailogErrMessage;

	/** checked GroupId */
	public String checkGroupId;
}
