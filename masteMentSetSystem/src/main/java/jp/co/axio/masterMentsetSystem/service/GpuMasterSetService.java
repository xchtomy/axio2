package jp.co.axio.masterMentsetSystem.service;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.controller.GpuMasterSetForm;
import jp.co.axio.masterMentsetSystem.dto.CodeValueDto;
import jp.co.axio.masterMentsetSystem.dto.GpuMasterSetDto;
import jp.co.axio.masterMentsetSystem.model.MgpCodeMst;
import jp.co.axio.masterMentsetSystem.model.MgpCodeMstKey;
import jp.co.axio.masterMentsetSystem.repository.MgpCodeMstMapper;
import jp.co.axio.masterMentsetSystem.repository.MgpCodeMstSelectMapper;

/**
 * 汎用コードマスタ設定画面サービスクラス
 *
 * @author JCBC
 * @version 1.0
 */
@Service
public class GpuMasterSetService {

    private final String delimiter = "：";

	/** 分類コードID */
	private final String classCodeId = "00000";

	/** 分類コードID */
	private final String classCodeName= "分類名称管理マスタ";

    /* 汎用コードマスタ */
    @Autowired
    MgpCodeMstSelectMapper MgpCodeMstSelectMapper;

    @Autowired
    MgpCodeMstMapper MgpCodeMstMapper;

    /**
     * 汎用コード情報検索条件用データ取得 select
     * @return 汎用コード情報検索条件用データ
     */
    @Transactional
    public List<MgpCodeMst> selectMgpCodeMstSearch () {
        LogService.info("汎用コードマスタ設定画面", "GpuMasterSetService", "分類コード名称リスト検索処理", "開始");

		Boolean checkflg = false;

		List<MgpCodeMst> classCodeInfo = MgpCodeMstSelectMapper.selectMgpCodeMstSearchByclassCode();
		for(MgpCodeMst mgpCodeMst: classCodeInfo){
			if (mgpCodeMst.getCodeValue().equals(classCodeId)) {
				checkflg =true;
			}
		}

		if (!checkflg) {
			MgpCodeMst mgpCodeMst = new MgpCodeMst();
			mgpCodeMst.setCodeValue(classCodeId);
			mgpCodeMst.setGpCodeMstName(classCodeName);
			classCodeInfo.add(0, mgpCodeMst);
		}

        LogService.info("汎用コードマスタ設定画面", "GpuMasterSetService", "分類コード名称リスト検索処理", "正常終了");
    	return classCodeInfo;
    }

    /**
     * 汎用マスタ分類リスト取得 select
     * @param classCode 分類コード
     * @return 汎用マスタ分類情報
     */
    @Transactional
    public List<CodeValueDto> selectValueSearch (String classCodeId) throws Exception{
        LogService.info("汎用コードマスタ設定画面", "GpuMasterSetService", "分類リスト検索処理", "開始");
    	List<CodeValueDto> classCodeValueList = new ArrayList<>();
		/*
		 * CodeValueDto codeValueDto = new CodeValueDto();
		 * codeValueDto.setCodeValue("0"); codeValueDto.setCodeName("");
		 * classCodeValueList.add(codeValueDto);
		 */
    	CodeValueDto codeValueDto = null;
    	MgpCodeMstKey MgpCodeMstKey = new MgpCodeMstKey();
    	MgpCodeMstKey.setClassCode("00000");
    	MgpCodeMstKey.setCodeValue(classCodeId);
	       MgpCodeMst MgpCodeMstOut = MgpCodeMstMapper.selectByPrimaryKey(MgpCodeMstKey);
	       StringBuilder classCode = null;
	       StringBuilder classValue = null;

	       for (int i= 0;i<15;i++) {

		       codeValueDto = new CodeValueDto();
		       classCode = new StringBuilder();
		       classValue = new StringBuilder();
		       classCode.append((i+1));
		       classValue.append((i+1));
		       classValue.append(delimiter);

		       codeValueDto.setCodeValue(classCode.toString());
				if (MgpCodeMstOut != null) {
					switch (i) {
					case 0:
						if (StringUtils.isNotEmpty(MgpCodeMstOut.getValue1())) {
							classValue.append(" ");
							classValue.append(MgpCodeMstOut.getValue1());
						}
						break;
					case 1:
						if (StringUtils.isNotEmpty(MgpCodeMstOut.getValue2())) {
							classValue.append(" ");
							classValue.append(MgpCodeMstOut.getValue2());
						}
						break;
					case 2:
						if (StringUtils.isNotEmpty(MgpCodeMstOut.getValue3())) {
							classValue.append(" ");
							classValue.append(MgpCodeMstOut.getValue3());
						}
						break;
					case 3:
						if (StringUtils.isNotEmpty(MgpCodeMstOut.getValue4())) {
							classValue.append(" ");
							classValue.append(MgpCodeMstOut.getValue4());
						}
						break;
					case 4:
						if (StringUtils.isNotEmpty(MgpCodeMstOut.getValue5())) {
							classValue.append(" ");
							classValue.append(MgpCodeMstOut.getValue5());
						}
						break;
					case 5:
						if (StringUtils.isNotEmpty(MgpCodeMstOut.getValue6())) {
							classValue.append(" ");
							classValue.append(MgpCodeMstOut.getValue6());
						}
						break;
					case 6:
						if (StringUtils.isNotEmpty(MgpCodeMstOut.getValue7())) {
							classValue.append(" ");
							classValue.append(MgpCodeMstOut.getValue7());
						}
						break;
					case 7:
						if (StringUtils.isNotEmpty(MgpCodeMstOut.getValue8())) {
							classValue.append(" ");
							classValue.append(MgpCodeMstOut.getValue8());
						}
						break;
					case 8:
						if (StringUtils.isNotEmpty(MgpCodeMstOut.getValue9())) {
							classValue.append(" ");
							classValue.append(MgpCodeMstOut.getValue9());
						}
						break;
					case 9:
						if (StringUtils.isNotEmpty(MgpCodeMstOut.getValue10())) {
							classValue.append(" ");
							classValue.append(MgpCodeMstOut.getValue10());
						}
						break;
					case 10:
						if (StringUtils.isNotEmpty(MgpCodeMstOut.getValue11())) {
							classValue.append(" ");
							classValue.append(MgpCodeMstOut.getValue11());
						}
						break;
					case 11:
						if (StringUtils.isNotEmpty(MgpCodeMstOut.getValue12())) {
							classValue.append(" ");
							classValue.append(MgpCodeMstOut.getValue12());
						}
						break;
					case 12:
						if (StringUtils.isNotEmpty(MgpCodeMstOut.getValue13())) {
							classValue.append(" ");
							classValue.append(MgpCodeMstOut.getValue13());
						}
						break;
					case 13:
						if (StringUtils.isNotEmpty(MgpCodeMstOut.getValue14())) {
							classValue.append(" ");
							classValue.append(MgpCodeMstOut.getValue14());
						}
						break;
					case 14:
						if (StringUtils.isNotEmpty(MgpCodeMstOut.getValue15())) {
							classValue.append(" ");
							classValue.append(MgpCodeMstOut.getValue15());
						}
						break;
					}
				}
				codeValueDto.setCodeName(classValue.toString());
				classCodeValueList.add(codeValueDto);
	       }

        LogService.info("汎用コードマスタ設定画面", "GpuMasterSetService", "分類リスト検索処理", "正常終了");
    	return classCodeValueList;
    }

    /**
     * 汎用マスタ分類リスト取得 select
     * @param classCode 分類コード
     * @return 汎用マスタ分類情報
     */
    @Transactional
    public Boolean codeValueCheck (String classCodeNo,String selectClassCodeValue) {
    	Boolean flag = false;
    	MgpCodeMstKey MgpCodeMstKey = new MgpCodeMstKey();
    	MgpCodeMstKey.setClassCode("00000");
    	MgpCodeMstKey.setCodeValue(classCodeNo);
	    MgpCodeMst MgpCodeMstOut = MgpCodeMstMapper.selectByPrimaryKey(MgpCodeMstKey);
	    if(MgpCodeMstOut== null ) {
	    	if (!selectClassCodeValue.equals("1")) {
				flag = true;
	    	}
			return flag;
	    }

		switch(selectClassCodeValue){
		case "2":
			if(StringUtils.isEmpty(MgpCodeMstOut.getValue1())) {
				flag = true;
			}
		    break;
		case "3":
			if(StringUtils.isEmpty(MgpCodeMstOut.getValue2())) {
				flag = true;
			}
		    break;
		case "4":
			if(StringUtils.isEmpty(MgpCodeMstOut.getValue3())) {
				flag = true;
			}
		    break;
		case "5":
			if(StringUtils.isEmpty(MgpCodeMstOut.getValue4())) {
				flag = true;
			}
		    break;
		case "6":
			if(StringUtils.isEmpty(MgpCodeMstOut.getValue5())) {
				flag = true;
			}
		    break;
		case "7":
			if(StringUtils.isEmpty(MgpCodeMstOut.getValue6())) {
				flag = true;
			}
		    break;
		case "8":
			if(StringUtils.isEmpty(MgpCodeMstOut.getValue7())) {
				flag = true;
			}
		    break;
		case "9":
			if(StringUtils.isEmpty(MgpCodeMstOut.getValue8())) {
				flag = true;
			}
		    break;
		case "10":
			if(StringUtils.isEmpty(MgpCodeMstOut.getValue9())) {
				flag = true;
			}
		    break;
		case "11":
			if(StringUtils.isEmpty(MgpCodeMstOut.getValue10())) {
				flag = true;
			}
		    break;
		case "12":
			if(StringUtils.isEmpty(MgpCodeMstOut.getValue11())) {
				flag = true;
			}
		    break;
		case "13":
			if(StringUtils.isEmpty(MgpCodeMstOut.getValue12())) {
				flag = true;
			}
		    break;
		case "14":
			if(StringUtils.isEmpty(MgpCodeMstOut.getValue13())) {
				flag = true;
			}
		    break;
		case "15":
			if(StringUtils.isEmpty(MgpCodeMstOut.getValue14())) {
				flag = true;
			}
		    break;
		}

		return flag;

    }

    /**
     * 汎用マスタ値取得 select
     * @return 汎用マスタ値情報
     */
    @Transactional
    public List<GpuMasterSetDto> selectMgpCodeMstSearchByGpuMasterSet (String selectClassCodeValue, String classCodeId) throws Exception{

        LogService.info("汎用コードマスタ設定画面", "GpuMasterSetService", "値編集のリスト検索処理", "開始");
		List<GpuMasterSetDto> selectValueLista  = new ArrayList<>();
        //リスト空に選択時に、画面一覧データにクリア
		if (selectClassCodeValue.equals("0")) {
        	return selectValueLista;
        }
		List<MgpCodeMst> selectValueList = MgpCodeMstSelectMapper.selectMgpCodeMstSearchByGpuMasterSet(classCodeId);

		GpuMasterSetDto outputDto = null;
		for(MgpCodeMst MgpCodeMst: selectValueList){
			outputDto = new GpuMasterSetDto();
			outputDto.setClassCode(MgpCodeMst.getClassCode());
			outputDto.setCodeValue(MgpCodeMst.getCodeValue());
			outputDto.setGpCodeMstName(MgpCodeMst.getGpCodeMstName());
			switch(selectClassCodeValue){
			case "1":
				outputDto.setValue(MgpCodeMst.getValue1());
			    break;
			case "2":
				outputDto.setValue(MgpCodeMst.getValue2());
			    break;
			case "3":
				outputDto.setValue(MgpCodeMst.getValue3());
			    break;
			case "4":
				outputDto.setValue(MgpCodeMst.getValue4());
			    break;
			case "5":
				outputDto.setValue(MgpCodeMst.getValue5());
			    break;
			case "6":
				outputDto.setValue(MgpCodeMst.getValue6());
			    break;
			case "7":
				outputDto.setValue(MgpCodeMst.getValue7());
			    break;
			case "8":
				outputDto.setValue(MgpCodeMst.getValue8());
			    break;
			case "9":
				outputDto.setValue(MgpCodeMst.getValue9());
			    break;
			case "10":
				outputDto.setValue(MgpCodeMst.getValue10());
			    break;
			case "11":
				outputDto.setValue(MgpCodeMst.getValue11());
			    break;
			case "12":
				outputDto.setValue(MgpCodeMst.getValue12());
			    break;
			case "13":
				outputDto.setValue(MgpCodeMst.getValue13());
			    break;
			case "14":
				outputDto.setValue(MgpCodeMst.getValue14());
			    break;
			case "15":
				outputDto.setValue(MgpCodeMst.getValue15());
			    break;
			}
			outputDto.setDispOrder(MgpCodeMst.getDispOrder());
			outputDto.setVersionNumber(MgpCodeMst.getVersionNumber());
			selectValueLista.add(outputDto);

		}
    	LogService.info("汎用コードマスタ設定画面", "GpuMasterSetService", "値編集のリスト検索処理", "正常終了");
    	return selectValueLista;
    }

    /**
     * 汎用コードマスタ登録・更新・削除処理
     */
    @Transactional
    public void saveData(GpuMasterSetForm form, List<GpuMasterSetDto> selectClassCodeList) throws Exception{
        LogService.info("汎用コードマスタ設定画面", "GpuMasterSetService", "汎用コードマスタ登録・更新・削除処理", "開始");
		for(GpuMasterSetDto editDto: selectClassCodeList){
		    if(StringUtils.isEmpty(editDto.editClass)){
			continue;
		    } else if (editDto.editClass.equals("1")) {
		    	MgpCodeMstKey MgpCodeMstKey = new MgpCodeMstKey();
		    	MgpCodeMstKey.setClassCode(editDto.getClassCode());
		    	MgpCodeMstKey.setCodeValue(editDto.getCodeValue());
			    MgpCodeMst MgpCodeMstOut = MgpCodeMstMapper.selectByPrimaryKey(MgpCodeMstKey);
			    if(MgpCodeMstOut != null ) {
		            editDto.setEditClass("2");
			    }
		    }
		    switch(editDto.editClass){
		    case "1":
			// 登録処理
			MgpCodeMst insertEntity = new MgpCodeMst();


			insertEntity.setClassCode(editDto.getClassCode());
			insertEntity.setCodeValue(editDto.getCodeValue());
			insertEntity.setGpCodeMstName(editDto.gpCodeMstName);;
			switch(form.getSelectClassCodeValue()){
			case "1":
			    insertEntity.setValue1(editDto.getValue());
			    break;
			case "2":
			    insertEntity.setValue2(editDto.getValue());
			    break;
			case "3":
			    insertEntity.setValue3(editDto.getValue());
			    break;
			case "4":
			    insertEntity.setValue4(editDto.getValue());
			    break;
			case "5":
			    insertEntity.setValue5(editDto.getValue());
			    break;
			case "6":
			    insertEntity.setValue6(editDto.getValue());
			    break;
			case "7":
			    insertEntity.setValue7(editDto.getValue());
			    break;
			case "8":
			    insertEntity.setValue8(editDto.getValue());
			    break;
			case "9":
			    insertEntity.setValue9(editDto.getValue());
			    break;
			case "10":
			    insertEntity.setValue10(editDto.getValue());
			    break;
			case "11":
			    insertEntity.setValue11(editDto.getValue());
			    break;
			case "12":
			    insertEntity.setValue12(editDto.getValue());
			    break;
			case "13":
			    insertEntity.setValue13(editDto.getValue());
			    break;
			case "14":
			    insertEntity.setValue14(editDto.getValue());
			    break;
			case "15":
			    insertEntity.setValue15(editDto.getValue());
			    break;
			}

		    if(StringUtils.isNotBlank(editDto.dispOrder)) {
				insertEntity.setDispOrder(editDto.dispOrder);
		    }

			insertEntity.setDeleteFlag("0");
			insertEntity.setVersionNumber(new Integer("1"));
			MgpCodeMstMapper.insertSelective(insertEntity);
			break;

		    case "2":
				MgpCodeMst updateEntity = new MgpCodeMst();


				updateEntity.setClassCode(form.getClassCodeId());
				updateEntity.setCodeValue(editDto.getCodeValue());
				updateEntity.setGpCodeMstName(editDto.gpCodeMstName);
				switch(form.getSelectClassCodeValue()){
				case "1":
					updateEntity.setValue1(editDto.getValue());
				    break;
				case "2":
					updateEntity.setValue2(editDto.getValue());
				    break;
				case "3":
					updateEntity.setValue3(editDto.getValue());
				    break;
				case "4":
					updateEntity.setValue4(editDto.getValue());
				    break;
				case "5":
					updateEntity.setValue5(editDto.getValue());
				    break;
				case "6":
					updateEntity.setValue6(editDto.getValue());
				    break;
				case "7":
					updateEntity.setValue7(editDto.getValue());
				    break;
				case "8":
					updateEntity.setValue8(editDto.getValue());
				    break;
				case "9":
					updateEntity.setValue9(editDto.getValue());
				    break;
				case "10":
					updateEntity.setValue10(editDto.getValue());
				    break;
				case "11":
					updateEntity.setValue11(editDto.getValue());
				    break;
				case "12":
					updateEntity.setValue12(editDto.getValue());
				    break;
				case "13":
					updateEntity.setValue13(editDto.getValue());
				    break;
				case "14":
					updateEntity.setValue14(editDto.getValue());
				    break;
				case "15":
					updateEntity.setValue15(editDto.getValue());
				    break;
				}

		    if(StringUtils.isNotBlank(editDto.dispOrder)) {
		    	updateEntity.setDispOrder(editDto.dispOrder);;
		    }
			updateEntity.setDeleteFlag("0");

			MgpCodeMstMapper.updateByPrimaryKeySelective(updateEntity);
			break;
		    case "3":
			// 削除処理
			MgpCodeMst deleteEntity = new MgpCodeMst();

			deleteEntity.setClassCode(form.getClassCodeId());
			deleteEntity.setCodeValue(editDto.getCodeValue());
			deleteEntity.setDeleteFlag("1");
			deleteEntity.setVersionNumber(new Integer(editDto.getVersionNumber()+1));
			MgpCodeMstMapper.updateByPrimaryKeySelective(deleteEntity);
			break;
		    }

		}
        LogService.info("汎用コードマスタ設定画面", "GpuMasterSetService", "汎用コードマスタ登録・更新・削除処理", "正常終了");
	    }

}
