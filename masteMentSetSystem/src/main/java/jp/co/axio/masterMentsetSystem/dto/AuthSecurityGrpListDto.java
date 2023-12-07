package jp.co.axio.masterMentsetSystem.dto;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AuthSecurityGrpListDto {
    
    /**
     * セキュリティグループコード
     */
    public String securityGroupCode;

    /**
     * グループ名
     */
	public String groupName;

    /**
     * 開始日
     */
	public String startDate;

    /**
     * 終了日
     */
	public String endDate;

    /**
     * 備考
     */
	public String note;

	/** 
     * 表示フラグ
     */
	public boolean dispFlag;

	/** チェックフラグ*/
	public boolean checkFlag;

}
