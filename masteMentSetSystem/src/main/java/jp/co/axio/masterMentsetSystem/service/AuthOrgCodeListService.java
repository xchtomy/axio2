package jp.co.axio.masterMentsetSystem.service;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.controller.AuthOrgCodeListController;
import jp.co.axio.masterMentsetSystem.dto.AuthOrgCodeListDto;
import jp.co.axio.masterMentsetSystem.model.MOrganizationEntity;
import jp.co.axio.masterMentsetSystem.repository.MOrganizationEntityMapper;

/**
 * 組織コード一覧画面サービスクラス
 *
 * @author axio
 * @version 1.0
 */
@Service
public class AuthOrgCodeListService {

    /* 組織マスタ */
    @Autowired
    MOrganizationEntityMapper mOrganizationEntityMapper;

    /**
     * 組織情報検索処理
     *
     * @param selectedCodeMapList - 選択済みコードのマップリスト（List<Map<String, String>>）
     * @param checkedCodeMapList - チェックコードのマップリスト（List<Map<String, String>>）
     * @param searchFlag - true:検索条件の検索をする／false:検索条件の検索をしない（選択済みの組織のみ）（boolean）
     * @param searchCompanyCode - 検索する会社コード（String）
     * @param searchDepartmentCode - 検索する組織コード（String）
     * @param searchDepartmentName - 検索する組織名（String）
     * @param searchStartDateYmd - 検索する有効基準日（String）
     * @param searchEndDateYmd - 未使用（String）
     * @return 組織情報リスト（List<AuthOrgCodeListDto>）
     */
    @Transactional
    public List<AuthOrgCodeListDto> selectMOrganization(List<Map<String, String>> selectedCodeMapList
    													, List<Map<String, String>> checkedCodeMapList
    													, boolean searchFlag
    													, String searchCompanyCode
    													, String searchDepartmentCode
    													, String searchDepartmentName
    													, String searchStartDateYmd
    													, String searchEndDateYmd) {
		List<AuthOrgCodeListDto> result = new ArrayList<AuthOrgCodeListDto>();
        LogService.info(AuthOrgCodeListController.OWN_TITLE, this.getClass().getSimpleName(), "組織情報検索処理", "開始");

        List<MOrganizationEntity> mOrganizationEntityList = null;
        if (selectedCodeMapList == null) selectedCodeMapList = new ArrayList<Map<String, String>>();
        if (checkedCodeMapList == null) checkedCodeMapList = new ArrayList<Map<String, String>>();
        if (searchCompanyCode == null) searchCompanyCode = "";
        if (searchDepartmentCode == null) searchDepartmentCode = "";
        if (searchDepartmentName == null) searchDepartmentName = "";
        if (searchStartDateYmd == null) searchStartDateYmd = "";
        if (searchEndDateYmd == null) searchEndDateYmd = "";

        Set<String> selectedCodeSet = new HashSet<String>();
		Set<String> checkedCodeSet = new HashSet<String>();
        List<Map<String, String>> codeMapList = new ArrayList<Map<String, String>>();
        for (Map<String, String> map:selectedCodeMapList) {
        	if (map != null
        			&& map.containsKey(AuthOrgCodeListController.CALL_PARAMETER_DATA_KEY1)
        			&& map.containsKey(AuthOrgCodeListController.CALL_PARAMETER_DATA_KEY1)) {
        		String val = new StringBuffer()
									.append(map.get(AuthOrgCodeListController.CALL_PARAMETER_DATA_KEY1))
									.append(":")
									.append(map.get(AuthOrgCodeListController.CALL_PARAMETER_DATA_KEY2))
									.toString();
        		selectedCodeSet.add(val);
        		codeMapList.add(map);
        	}
        }
        for (Map<String, String> map:checkedCodeMapList) {
        	if (map != null
        			&& map.containsKey(AuthOrgCodeListController.CALL_PARAMETER_DATA_KEY1)
        			&& map.containsKey(AuthOrgCodeListController.CALL_PARAMETER_DATA_KEY1)) {
        		String val = new StringBuffer()
									.append(map.get(AuthOrgCodeListController.CALL_PARAMETER_DATA_KEY1))
									.append(":")
									.append(map.get(AuthOrgCodeListController.CALL_PARAMETER_DATA_KEY2))
									.toString();
        		checkedCodeSet.add(val);
        		//if (!selectedCodeSet.contains(val)) codeMapList.add(map);
        	}
        }

        if (searchFlag || codeMapList.size() > 0) {
			// 「\」「%」をエスケープ
			if (searchCompanyCode.indexOf("\\") >= 0) searchCompanyCode = searchCompanyCode.replace("\\", "\\\\");
			if (searchCompanyCode.indexOf("%") >= 0) searchCompanyCode = searchCompanyCode.replace("%", "\\%");
			if (searchDepartmentCode.indexOf("\\") >= 0) searchDepartmentCode = searchDepartmentCode.replace("\\", "\\\\");
			if (searchDepartmentCode.indexOf("%") >= 0) searchDepartmentCode = searchDepartmentCode.replace("%", "\\%");
			if (searchDepartmentName.indexOf("\\") >= 0) searchDepartmentName = searchDepartmentName.replace("\\", "\\\\");
			if (searchDepartmentName.indexOf("%") >= 0) searchDepartmentName = searchDepartmentName.replace("%", "\\%");
			mOrganizationEntityList = mOrganizationEntityMapper.selectMOrganizationByAuthOrgCodeList(codeMapList
																								, searchFlag
																								, searchCompanyCode
																								, searchDepartmentCode
																								, searchDepartmentName
																								, searchStartDateYmd
																								, searchEndDateYmd);
        }
		if (mOrganizationEntityList != null) {
			List<AuthOrgCodeListDto> list = new ArrayList<AuthOrgCodeListDto>();
			for (MOrganizationEntity mOrganizationEntity : mOrganizationEntityList) {
				AuthOrgCodeListDto dto = new AuthOrgCodeListDto();
				dto.setCompanyCode(mOrganizationEntity.getCompanyCode());
				dto.setDepartmentCode(mOrganizationEntity.getOrganizationCode());
				dto.setDepartmentNameJp(mOrganizationEntity.getOrganizationNameJp());
				dto.setStartDateYmd(dateToString(mOrganizationEntity.getStartDate()));
				dto.setEndDateYmd(dateToString(mOrganizationEntity.getEndDate()));
        		String val = new StringBuffer()
        							.append(dto.getCompanyCode())
        							.append(":")
        							.append(dto.getDepartmentCode())
        							.toString();
				if (selectedCodeSet.contains(val)) {
					// 選択済みのデータ
					dto.setSelectedFlag(true);
				} else {
					// 未選択のデータ
					dto.setSelectedFlag(false);
				}
				if (checkedCodeSet.contains(val)) {
					// チェックのデータ
					dto.setCheckedFlag(true);
				} else {
					// 未チェックのデータ
					dto.setCheckedFlag(false);
				}
				if (dto.isSelectedFlag()) {
					result.add(dto);
				} else {
					list.add(dto);
				}
			}
			result.addAll(list);
		}

		LogService.info(AuthOrgCodeListController.OWN_TITLE, this.getClass().getSimpleName(), "組織情報検索処理", "正常終了");
    	return result;
    }

    /**
     * 日付型を日付文字列（yyyy/MM/dd）に変換する。
     *
     * @param dt - 日付（Date）
     * @return 日付文字列（String）
     */
    private String dateToString(Date dt) {
    	String result = "";

    	if (dt != null) {
			SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd");
			result = sdf.format(dt);
    	}

    	return result;
    }
}
