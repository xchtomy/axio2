package jp.co.axio.masterMentsetSystem.model;

import java.util.Date;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VGamenUserEntity {
	/** 在籍区分 */
    private String enrollmentName;
	/** ユーザーID */
    private String userId;
	/** 雇用区分 */
    private String employmentKbn;
	/** 雇用名称 */
    private String employmentName;
	/** 氏名（漢字） */
    private String nameJp;
	/** 氏名（ローマ字） */
    private String nameEn;
	/** 氏名（カタカナ） */
    private String nameKana;
	/** 英語姓 */
    private String surnameEn;
	/** 英語名 */
    private String givennameEn;
	/** 所属部コード */
    private String organizationCode;
	/** 所属部署（英語） */
    private String organizationNameEn;
	/** 所属部署 */
    private String organizationNameJp;
	/** 役職コード */
    private String positionCode;
	/** 役職名（英語）*/
    private String positionNameEn;
	/** 役職名 */
    private String positionNameJp;
	/** 有効開始日 */
    private Date startDate;
	/** 有効終了日 */
    private Date endDate;
	/** 在職区分 */
    private String enrollmentKbn;
	/** ログインID */
    private String loginId;
	/** 会社コード */
    private String companyCode;
	/** 元所属コード */
    private String orgOrganizationCode;
	/** 言語コード */
    private String langCode;
	/** 言語名称 */
    private String langName;
	/** メールアドレス（メイン） */
    private String mailaddrNotification;
	/** メールアドレス（サブ） */
    private String mailaddr;
    /** 外線番号 */
   private String tel;
	/** 内線番号 */
    private String telEx;
	/** 「Win」設定値 */
    private String expansionAttr11;
	/** 「WWW」設定値 */
    private String expansionAttr12;
	/** 「社内メール」設定値 */
    private String expansionAttr13;
	/** 「E_mail」設定値 */
    private String expansionAttr14;
	/** 「SAP」設定値 */
    private String expansionAttr15;
	/** 「POP」設定値 */
    private String expansionAttr16;
	/** 「POP(EUC)」設定値 */
    private String expansionAttr17;
	/** 「釣基幹」設定値 */
    private String expansionAttr18;
	/** 「GSPI」設定値 */
    private String expansionAttr19;
	/** 「SSS」設定値 */
    private String expansionAttr21;
	/**「自Web」設定値 */
    private String expansionAttr22;
	/** 「製品遺産在庫」設定値 */
    private String expansionAttr23;
	/** 「EDI」設定値 */
    private String expansionAttr24;
	/** 「GSPI(DWH)」設定値 */
    private String expansionAttr25;
	/** 原価センタ */
    private String expansionAttr36;
    /** 派遣会社名 */
    private String expansionAttr37;
    /** 拠点名 */
    private String hubName;
    /** 人事領域名 */
    private String companyName;
}