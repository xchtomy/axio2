package jp.co.axio.masterMentsetSystem.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * 組織コード一覧画面Dto
 *
 * @author axio
 */
@Setter
@Getter
public class AuthOrgCodeListDto {

	/** 選択済みフラグ */
	private boolean selectedFlag;

	/** チェックフラグ */
	private boolean checkedFlag;

	/** 会社コード */
	private String companyCode;

	/** 組織コード */
	private String departmentCode;

	/** 組織名称 */
	private String departmentNameJp;

	/** 適用開始日(yyyy/MM/dd形式） */
	private String startDateYmd;

	/** 適用終了日(yyyy/MM/dd形式） */
	private String endDateYmd;
}