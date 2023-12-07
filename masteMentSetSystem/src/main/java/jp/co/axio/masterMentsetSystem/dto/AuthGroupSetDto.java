package jp.co.axio.masterMentsetSystem.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * グループ設定画面Dto
 *
 * @author AXIO
 */
@Setter
@Getter
public class AuthGroupSetDto {
    private String ruleId;

    private String ruleName;

    private String ruleNote;

    private String rulePeriod;

}