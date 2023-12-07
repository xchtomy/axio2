package jp.co.axio.masterMentsetSystem.controller;

import java.io.Serializable;
import java.util.List;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import javax.validation.groups.Default;

import jp.co.axio.masterMentsetSystem.dto.AuthGroupSetDto;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AuthGroupSetForm extends accessForm implements Serializable {

	/**
	* グループ設定画面フォーム
	 */
	private static final long serialVersionUID = 1L;

	// グループ保存ボタングループ
	interface SaveGroup extends Default{}

	// グループ削除ボタングループ
	interface DeleteGroup extends Default{}

	// 一覧反映ボタングループ
	interface ReflectionGroup extends Default{}

	/** 検索フラグ １： グループ検索押下より値取得された場合*/
	public String searchFlg;

	/** グループ編集フラグ　１：グループテキストエリアの値が変更ある場合 */
	public String editFlg;

	/** グループ条件変更フラグ 　１：テキストボックスの値が変更ある場合*/
	public String changedFlg;

	/** CallBack　function name */
	public String reflectFunction;

	/** ダイヤログから選択された値 */
	public String paramVal;

	/** Error message */
	public String errMessage;

	/** グループ関連ルール情報リスト */
	public List<AuthGroupSetDto> groupRuleList;

	/** グループID */
	@NotBlank(groups = {DeleteGroup.class})
	public String groupId;

	/** グループ名（英語） 廃止*/
//	@NotBlank(groups = {SaveGroup.class})
//	@Size(min = 1, max = 256, groups = {SaveGroup.class})
	public String groupNameEn;

	/** グループ名 */
	@NotBlank(groups = {SaveGroup.class})
	@Size(min = 1, max = 256, groups = {SaveGroup.class})
	public String groupNameJp;

	/** 開始日 */
//	@AxioDateFormat(groups = {SaveGroup.class})
	@NotBlank(groups = {SaveGroup.class})
	public String groupStartDate;

	/** 終了日 */
//	@AxioDateFormat(groups = {SaveGroup.class})
	@NotBlank(groups = {SaveGroup.class})
	public String groupEndDate;

	/** 備考 */
	@Size(max = 2000, groups = {SaveGroup.class})
	public String groupDetail;

}
