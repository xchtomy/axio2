package jp.co.axio.masterMentsetSystem.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * ユーザ詳細画面Dto
 *
 * @author axio
 */
@Setter
@Getter
public class UserDetailDto {

	/** 在籍区分 */
	private String enrollmentName;
	/** ユーザーID */
	private String userId;
	/** 雇用名称	※区分 */
	private String employmentName;
	/** 氏名（英語） */
	private String nameEn;
	/** 氏名 */
	private String nameJp;
	/** 所属部署コード */
	private String organizationCode;
	/** 所属部署（英語） */
	private String organizationNameEn;
	/** 所属部署 */
	private String organizationNameJp;
	/** 役職名 */
	private String positionNameJp;
	/** 有効開始日 */
	private String startDate;
	/** 有効終了日（退職予定日） */
	private String endDate;
	/** ログインID */
	private String loginId;
	/** 会社コード */
    private String companyCode;
	/** 外線番号 */
	private String tel;
	/** 内線番号*/
	private String telEx;
	/** 利用言語 */
	private String langName;
	/** メールアドレス（メイン） */
	private String mailaddrNotification;
	/** メールアドレス（サブ） */
	private String mailaddr;

}
