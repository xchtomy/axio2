package jp.co.axio.masterMentsetSystem.model;



import java.util.Date;

import lombok.Data;

@Data
public class MOrganizationAdGroupEntity {

    /**
     * SGグループID
     */
    private String securityGroupCode;
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
     * 開始日
     */
    private Date startDate;

    /**
     * 終了日
     */
    private Date endDate;

    /**
     * 反映日
     */
    private Date reflectionDate;
    /**
     * 備考
     */
    private String note;
    /**
     * 無効フラグ
     */
    private String invalidFlag;
    /**
     * 拡張属性１
     */
    private String optionAttr1;
    /**
     * 拡張属性２
     */
    private String optionAttr2;
    /**
     * 拡張属性３
     */
    private String optionAttr3;
    /**
     * 拡張属性４
     */
    private String optionAttr4;
    /**
     * 拡張属性５
     */
    private String optionAttr5;
    /**
     * 拡張属性６
     */
    private String optionAttr6;
    /**
     * 拡張属性７
     */
    private String optionAttr7;
    /**
     * 拡張属性８
     */
    private String optionAttr8;
    /**
     * 拡張属性９
     */
    private String optionAttr9;
    /**
     * 拡張属性１０
     */
    private String optionAttr10;

    /**
     * 登録ID
     */
    private String registerId;

    /**
     * 登録タイムスタンプ
     */
    private Date registTs;

    /**
     * 更新ID
     */
    private String updaterId;

    /**
     * 更新タイムスタンプ
     */
    private Date updateTs;

}
