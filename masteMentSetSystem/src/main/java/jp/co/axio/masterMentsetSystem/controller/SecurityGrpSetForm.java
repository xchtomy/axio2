package jp.co.axio.masterMentsetSystem.controller;

import java.io.Serializable;
import java.util.List;

import javax.validation.constraints.NotBlank;

import lombok.Getter;
import lombok.Setter;

/**
 * 組織コード一覧フォーム
 */
@Setter
@Getter
public class SecurityGrpSetForm extends accessForm implements Serializable {


    /**
     * 会社コード
     */
    private String companyCode;

	 /**
     * 組織コード
     */
    private String organizationCode;

    /**
     * 組織名
     */
    private String organizationName;

	/**
	 * 基本設定
	 * 表
	 */
    private List<SecurityGrpBaseParam> securityGrpBaseList;

    /**
     * 反映日
     */
    // @NotBlank(message = "『反映日』は必須項目です。")
    private String reflectionDate;

	/**
	 * エラーメッセージ
	 */
	private String errMessage;


    /**
     * 警告メッセージ
     */
    private String wanMessage;

    /**
     * 警告先URL
     */
    private String wanUrl;


    /**
     * 警告チェック
     */
    private String wanCheck;

    // 隠し属性
    /**
     * 選択されたSGID
     */
    private String selectSecurityGrpCode;

    /**
     * 組織重複フラグ
     */
    private String duplicatedOrg;


    /**
     * 詳細設定
     */
    /**
     * 拡張属性1
     */
    private String optionAttr1;

    /**
     * 拡張属性2
     */
    private String optionAttr2;
    
    /**
     * 拡張属性3
     */
    private String optionAttr3;

    /**
     * 拡張属性4
     */
    private String optionAttr4;
    
    /**
     * 拡張属性5
     */
    private String optionAttr5;

    /**
     * 拡張属性6
     */
    private String optionAttr6;

    /**
     * 拡張属性7
     */
    private String optionAttr7;

    /**
     * 拡張属性8
     */
    private String optionAttr8;

    /**
     * 拡張属性9
     */
    private String optionAttr9;

    /**
     * 拡張属性10
     */
    private String optionAttr10;



}
