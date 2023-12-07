package jp.co.axio.masterMentsetSystem.controller;

import java.io.Serializable;
import java.util.List;

import jp.co.axio.masterMentsetSystem.dto.UserMaxCntDto;
import jp.co.axio.masterMentsetSystem.model.VGamenUserEntity;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class UserListForm extends accessForm implements Serializable {

	/**
	 * ルール条件設定フォーム
	 */
	private static final long serialVersionUID = 1L;

	/** ユーザID */
	public String userId;

	/** ユーザ名 */
	public String userName;

	/** 所属名 */
	public String orgName;

	/** 英語姓 */
	public String surnameEn;

	/** 英語名 */
	public String givennameEn;

	/** 外線番号 */
	public String tel;

	/** 内線番号 */
	public String telEx;

	/** 無効チェックボックス */
	public String InvUserFlg;

	/** max件数リスト */
	public List<UserMaxCntDto> userMaxCntList;

	/** 選択したMax件数 */
	public String cntSelected;
	public Integer cntInt = 10;

	/** 詳細情報リスト  */
	public List<VGamenUserEntity> detailList;

	/** 表示ページ番号 */
	public String pageNo;

	public Integer offset;

	/** 表示ページ番号 */
	public String count;

	/** 画面並び順 */
	public String sortCondition;

	/** 並び順(検索用) */
	public String orderbyStr;

	/** 選択行 */
	public String curRowId;

   /** 件数チェック済みフラグ */
	public String countCheck;

	/** 検索ヒット件数フラグ */
	public String popupShowFlg;

	/** 検索結果ヒット件数がmax件数を超える */
	public String popupMsg;

	/** 前のページボタン表示 */
	public String prePageFlg;

	/** 次のページボタン表示 */
	public String nextPageFlg;

	/** 検索結果が0件の場合表示 */
	public String zeroCntFlg;

	/** CSVボタン制御フラグ */
	public String csvFlg;

	/** 総件数表示メッセージ */
	public String cntMessage;

	/** Error message */
	public String errMessage;

	/** 当日システム日付 */
	public String today;

}
