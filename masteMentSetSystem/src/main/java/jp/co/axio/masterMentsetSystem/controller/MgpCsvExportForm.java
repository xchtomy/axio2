package jp.co.axio.masterMentsetSystem.controller;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import javax.validation.groups.Default;

import org.apache.commons.lang3.StringUtils;
import org.hibernate.validator.constraints.Length;

import jp.co.axio.masterMentsetSystem.dto.CodeValueDto;
import jp.co.axio.masterMentsetSystem.dto.TargetViewInfoResultListDto;
import jp.co.axio.masterMentsetSystem.model.MgpCsvExportDefInfo;
import jp.co.axio.masterMentsetSystem.model.OutputScopeMst;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class MgpCsvExportForm extends accessForm implements Serializable {

	/**
	*
	*/
	private static final long serialVersionUID = 1L;

	// 再描画ボタングループ
	interface testRunGroup extends Default {
	}

	// 登録ボタングループ
	interface saveGroup extends Default {
	}

	/** CSVファイル情報 */
	public String selectClassCode;

	/** SCSVファイル情報選択戻る用 */
	private String selectClassCodeBak;

	/** CSVファイル情報リスト */
	private List<MgpCsvExportDefInfo> mgpCsvExportList;


	/** 文字コードリスト */
	private List<CodeValueDto> charCodeList;

	/** 出力対象リスト */
	private List<OutputScopeMst> mstExportList;

	/** 抽出元情報一覧 */
	public List<TargetViewInfoResultListDto> targetViewInfoList;

	/** 抽出元情報一覧 */
	public List<TargetViewInfoResultListDto> targetViewOutList;

	/** SQL番号 */
	private Integer sqlNo;

	/** システム名 */
	@NotBlank(groups = {saveGroup.class})
	@Size(min = 1, max = 30, groups = {saveGroup.class})
	private String systemId;

	/** 登録名 */
	@NotBlank(groups = {saveGroup.class})
	@Size(min = 1, max = 100, groups = {saveGroup.class})
	private String sqlRegisterName;

	/** 有効フラグ */
	private String validFlag;

	/** パス */
	private String parentFilePath;

	/** サブパス */
	@Size(min = 0, max = 80, groups = {saveGroup.class})
	private String subFilePath;

	/** ファイル名 */
	@NotBlank(groups = {saveGroup.class})
	@Size(min = 1, max = 50, groups = {saveGroup.class})
	private String fileName;

	/** ファイル拡張子 */
	private String fileClass;

	/** ファイル命名区分 */
	private String fileNamingClass;

	/** 文字コード */
	private String strCode;

	/** 区切り文字区分 */
	private String delimiterClass;

	/** 改行コード区分 */
	private String fileCodeFormatClass;

	/** 囲い文字区分 */
	private String separationDefClass;

	/** ヘッダー情報付与区分 */
	private String fileHeaderInfoClass;

	/** SQL出力テーブル名 */
	@NotBlank(groups = {testRunGroup.class})
	@NotBlank(groups = {saveGroup.class})
	private String sqlOutTableName;

	/** SQL出力テーブル名選択戻る用 */
	private String sqlOutTableNameBak;

	/** 抽出元情報データ */
	private String sqlInfoData;

	/** SQL出力情報 */
	private String sqlOutData;

	/** 出力元情報 */
	private String sourceInfo;

	/** 出力情報*/
	private String outputInfo;

	/** SQL項目定義 */
	private String sqlColumnDef;

	/** ↑ボタン */
	public String disabledBtnUp;

	/** ↓ボタン */
	public String disabledBtnDown;

	/** SQL条件定義 */
//	@NotBlank(groups = {testRunGroup.class})
//	@NotBlank(groups = {saveGroup.class})
	private String sqlWhereDef;

	/** 登録者統一ID */
	private String registerId;

	/** 登録日時 */
	private Date registTs;

	/** 更新者統一ID */
	private String updaterId;

	/** 更新日時 */
	private Date updateTs;

	/** バージョンNO */
	private Integer versionNumber;

	/** 編集フラグ */
	public String editFlg;

    /** 出力対象が選択済みか？ */
    public String saveFlg = "0";

    /** データ変更有り(項目変更) */
    public String changedDataRedrawFlg;

    /** データ変更有り(SQL条件定義 )？ */
    public String changedDataSqlWhereDefFlg;

	/** 変更フラグ */
	public String changedDataFlg;

	/** 抽出データ */
	public String sqlInputDataTxt;

    /**
     　　　* 登録ボタン 押下可能か判定
     *
     * @return true=>非活性
     */
    public boolean isDisabledSave() {
        return StringUtils.equals(saveFlg , "0") && !StringUtils.equals(changedDataFlg,"1") ;
    };
}
