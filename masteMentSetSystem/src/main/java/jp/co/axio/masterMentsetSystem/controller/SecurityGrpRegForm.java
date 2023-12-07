package jp.co.axio.masterMentsetSystem.controller;

import java.io.Serializable;
import java.util.List;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class SecurityGrpRegForm extends accessForm implements Serializable {

    /**
     * 組織SGコード
     */
    private String selectSecurityGrpCode;

    /**
	 * 基本設定
	 * 表
	 */
    private List<SecurityGrpBaseParam> securityGrpBaseList;


    /**
     * 開始日
     */
    private String startDate;

    /**
     * 終了日
     */
    private String endDate;


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
    
}
