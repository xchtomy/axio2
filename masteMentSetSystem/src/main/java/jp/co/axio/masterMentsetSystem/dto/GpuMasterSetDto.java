package jp.co.axio.masterMentsetSystem.dto;

import java.time.LocalDateTime;

import lombok.Getter;
import lombok.Setter;

/**
 * 汎用コードマスタ設定画面Dto
 *
 * @author JCBC
 */
@Setter
@Getter
public class GpuMasterSetDto {

    /** 分類コード */
    public String classCode;

    /** コード値 */
    public String codeValue;

    /** 名称 */
    public String gpCodeMstName;

    /** 値1 */
    public String value;

    /** 表示順 */
    public String dispOrder;

    /** 登録者統一ID */
    public String registerId;

    /** 登録日時 */
    public LocalDateTime registTs;

    /** 更新者統一ID */
    public String updaterId;

    /** 更新日時 */
    public LocalDateTime updateTs;

    /** 削除フラグ */
    public String deleteFlag;

    /** バージョンNO */
    public Integer versionNumber;

    /** 編集区分 1:追加 2:変更 3:削除 */
    public String editClass;

}