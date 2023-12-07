package jp.co.axio.masterMentsetSystem.controller;

import java.io.Serializable;

import lombok.Data;


/**
 * セキュリティグループ
 * 表
 */
@Data
public class SecurityGrpBaseParam implements Serializable {

    /**
     * SGID
     */
    private String securityGroupCode;

    /**
     * グループID
     */
    private String groupId;

    /**
     * グループ名
     */
    private String groupName;

    /**
     * ラベルNo
     */
    private String groupType;

    /**
     * ラベル名
     */
    private String groupTypeName;

    /**
     * 備考
     */
    private String note;

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
     * 開始日
     */
    private String startDate;

    /**
     * 終了日
     */
    private String endDate;

    /**
     * 反映日
     */
    private String reflectionDate;
}
