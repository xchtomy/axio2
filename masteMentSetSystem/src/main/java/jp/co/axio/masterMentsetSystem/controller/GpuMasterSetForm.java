package jp.co.axio.masterMentsetSystem.controller;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import javax.validation.groups.Default;

import org.apache.commons.lang3.StringUtils;
import org.hibernate.validator.constraints.Length;

import jp.co.axio.masterMentsetSystem.common.AxioNumeric;
import jp.co.axio.masterMentsetSystem.dto.CodeValueDto;
import jp.co.axio.masterMentsetSystem.dto.GpuMasterSetDto;
import jp.co.axio.masterMentsetSystem.model.MgpCodeMst;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class GpuMasterSetForm extends accessForm implements Serializable {

		/**
	 *
	 */
	private static final long serialVersionUID = 1L;

		// 検索ボタングループ
    	interface SearchGroup extends Default{}

    	// 選択ボタングループ
    	interface SelectGroup extends Default{}

    	// 反映ボタングループ
    	interface ReflectionGroup extends Default{}

    	// 登録ボタングループ
    	interface SaveGroup extends Default{}

    	// 削除ボタングループ
    	interface DeleteGroup extends Default{}

	/** 分類コードID */
	public String classCodeId;

	/** 分類コード名称 */
	public List<MgpCodeMst> gpCodeSearchList;

	/** 選択された分類コード名称 */
	@NotBlank(groups = {SearchGroup.class})
	public String selectClassCode;

	public String classCodeValue;

	/** 分類1 */
	public List<CodeValueDto> classCodeValueList;

	/** 分類選択一覧で選択された分類情報 */
	public String selectClassCodeValue;

	/** 分類選択一覧で選択された分類名称 */
	public String selectClassCodeName;

	/** コードリスト */
	public List<GpuMasterSetDto> selectClassCodeList;

	/** 値一覧（入力）；分類 */
	public String txtClassCode;

	/** 値一覧（入力）；コードNO */
	@NotBlank(groups = {ReflectionGroup.class})
	@Size(min = 1, max = 20, groups = {ReflectionGroup.class})
	public String classCodeNo;

	/** 値一覧（入力）；コード名称 */
	@NotBlank(groups = {ReflectionGroup.class})
	@Size(min = 1, max = 125, groups = {ReflectionGroup.class})
	public String classCodeName;

	/** 値一覧（入力）；コード内容 */
	@NotBlank(groups = {ReflectionGroup.class})
	@Size(min = 1, max = 250, groups = {ReflectionGroup.class})
	public String classCodeDetail;

	/** 値一覧（入力）；表示順 */
	@AxioNumeric(groups = {ReflectionGroup.class})
	@Size(max = 50)
	public String classCodeOrder;

	/** 汎用コード情報検索で選択された分類名称 */
	public String selectClassName;

	/** 編集フラグ */
	public String editFlg;

	/** 変更フラグ */
	public String changedDataFlg;

	/** 検索フラグ */
	public String searchFlg;

	/** 選択フラグ */
	public String selectFlg;

	public String deleteClassCodeNo;

	private List<String> classCodeCheck;

	public List<String> getCheckClassCode() {
	    if (classCodeCheck == null) {
		classCodeCheck = Collections.emptyList();
	    }
	    return classCodeCheck;
	}

	public void setCheckClassCode(List<String> classCodeCheck) {
	    this.classCodeCheck = classCodeCheck;
	}

	public boolean isDisabledBtnSelectClassCode(){
	    return (StringUtils.equals(searchFlg, "1"));
	}

	public boolean isDisabledBtnSave() {
	    return (!StringUtils.equals(editFlg, "1"));
	}

	public boolean isDisabledBtnSearch(){
	    return (!StringUtils.equals(selectFlg, "1"));
	}

}
