package jp.co.axio.masterMentsetSystem.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * 会社コード一覧画面Dto
 *
 * @author axio
 */
@Setter
@Getter
public class AuthComCodeListDto {

	/** 選択済みフラグ */
	private boolean selectedFlag;

	/** チェックフラグ */
	private boolean checkedFlag;

	/** 会社コード */
	private String companyCode;

	/** 会社名称 */
	private String companyName;
}