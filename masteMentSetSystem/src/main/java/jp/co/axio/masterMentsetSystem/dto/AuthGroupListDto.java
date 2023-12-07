package jp.co.axio.masterMentsetSystem.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * グループ一覧画面Dto
 *
 * @author AXIO
 */
@Setter
@Getter
public class AuthGroupListDto {
	public String groupId;

	public String groupNameEn;

	public String groupNameJp;

	public String startDate;

	public String endDate;

	public String note;

	/** 表示フラグ */
	public boolean dispFlag;

	/** チェックフラグ*/
	public boolean checkFlag;
}