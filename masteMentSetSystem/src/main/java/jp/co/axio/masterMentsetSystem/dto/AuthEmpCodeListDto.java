package jp.co.axio.masterMentsetSystem.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * 雇用区分コード一覧画面Dto
 *
 * @author axio
 */
@Setter
@Getter
public class AuthEmpCodeListDto {

	/** 選択済みフラグ */
	private boolean selectedFlag;

	/** チェックフラグ */
	private boolean checkedFlag;

	/** 雇用区分コード */
	private String employmentCode;

	/** 雇用区分名称 */
	private String employmentName;
}