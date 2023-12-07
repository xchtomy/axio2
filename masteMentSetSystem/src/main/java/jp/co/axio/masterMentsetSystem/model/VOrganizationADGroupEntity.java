package jp.co.axio.masterMentsetSystem.model;

import java.util.Date;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class VOrganizationADGroupEntity {

    /**
     * 組織SGコード
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
     * 無効フラグ
     */
    private String invalidFlag;
    

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
