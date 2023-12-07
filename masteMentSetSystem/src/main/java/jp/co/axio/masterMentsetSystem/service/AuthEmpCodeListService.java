package jp.co.axio.masterMentsetSystem.service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.controller.AuthEmpCodeListController;
import jp.co.axio.masterMentsetSystem.dto.AuthEmpCodeListDto;
import jp.co.axio.masterMentsetSystem.model.MgpCodeMst;
import jp.co.axio.masterMentsetSystem.repository.MgpCodeMstMapper;
import jp.co.axio.masterMentsetSystem.repository.MgpCodeMstSelectMapper;

/**
 * 雇用区分コード一覧画面サービスクラス
 *
 * @author axio
 * @version 1.0
 */
@Service
public class AuthEmpCodeListService {

    /* 汎用コードマスタ */
    @Autowired
    MgpCodeMstSelectMapper MgpCodeMstSelectMapper;

    @Autowired
    MgpCodeMstMapper MgpCodeMstMapper;

    /**
     * 雇用区分情報検索処理
     *
     * @param selectedCodeMapList - 選択済みコードのマップリスト（List<Map<String, String>>）
     * @param checkedCodeMapList - チェックコードのマップリスト（List<Map<String, String>>）
     * @param searchFlag - true:検索条件の検索をする／false:検索条件の検索をしない（選択済みの雇用区分のみ）（boolean）
     * @param searchEmploymentCode - 検索する雇用区分コード（String）
     * @param searchEmploymentName - 検索する雇用区分名（String）
     * @return 雇用区分情報リスト（List<AuthEmpCodeListDto>）
     */
    @Transactional
    public List<AuthEmpCodeListDto> selectMgpCodeMst (List<Map<String, String>> selectedCodeMapList
    													, List<Map<String, String>> checkedCodeMapList
    													, boolean searchFlag
    													, String searchEmploymentCode
    													, String searchEmploymentName) {
		List<AuthEmpCodeListDto> result = new ArrayList<AuthEmpCodeListDto>();
        LogService.info(AuthEmpCodeListController.OWN_TITLE, this.getClass().getSimpleName(), "雇用区分情報検索処理", "開始");

        List<MgpCodeMst> mgpCodeMstList = null;
        if (selectedCodeMapList == null) selectedCodeMapList = new ArrayList<Map<String, String>>();
        if (checkedCodeMapList == null) checkedCodeMapList = new ArrayList<Map<String, String>>();
        if (searchEmploymentCode == null) searchEmploymentCode = "";
        if (searchEmploymentName == null) searchEmploymentName = "";

        Set<String> selectedCodeSet = new HashSet<String>();
		Set<String> checkedCodeSet = new HashSet<String>();
        Set<String> codeSet = new HashSet<String>();
        for (Map<String, String> map:selectedCodeMapList) {
        	if (map != null && map.containsKey(AuthEmpCodeListController.CALL_PARAMETER_DATA_KEY)) {
        		String val = map.get(AuthEmpCodeListController.CALL_PARAMETER_DATA_KEY);
        		selectedCodeSet.add(val);
        	}
        }
        for (Map<String, String> map:checkedCodeMapList) {
        	if (map != null && map.containsKey(AuthEmpCodeListController.CALL_PARAMETER_DATA_KEY)) {
        		String val = map.get(AuthEmpCodeListController.CALL_PARAMETER_DATA_KEY);
        		checkedCodeSet.add(val);
        	}
        }
        codeSet.addAll(selectedCodeSet);
        //codeSet.addAll(checkedCodeSet);
        if (searchFlag || codeSet.size() > 0) {
			// 「\」「%」をエスケープ
			if (searchEmploymentCode.indexOf("\\") >= 0) searchEmploymentCode = searchEmploymentCode.replace("\\", "\\\\");
			if (searchEmploymentCode.indexOf("%") >= 0) searchEmploymentCode = searchEmploymentCode.replace("%", "\\%");
			if (searchEmploymentName.indexOf("\\") >= 0) searchEmploymentName = searchEmploymentName.replace("\\", "\\\\");
			if (searchEmploymentName.indexOf("%") >= 0) searchEmploymentName = searchEmploymentName.replace("%", "\\%");
			mgpCodeMstList = MgpCodeMstSelectMapper.selectMgpCodeMstByAuthEmpCodeList(codeSet
																					, searchFlag
																					, searchEmploymentCode
																					, searchEmploymentName);
        }
		if (mgpCodeMstList != null) {
			List<AuthEmpCodeListDto> list = new ArrayList<AuthEmpCodeListDto>();
			for (MgpCodeMst mgpCodeMst : mgpCodeMstList) {
				AuthEmpCodeListDto dto = new AuthEmpCodeListDto();
				dto.setEmploymentCode(mgpCodeMst.getValue1());
				dto.setEmploymentName(mgpCodeMst.getValue2());
				if (selectedCodeSet.contains(mgpCodeMst.getValue1())) {
					// 選択済みのデータ
					dto.setSelectedFlag(true);
				} else {
					// 未選択のデータ
					dto.setSelectedFlag(false);
				}
				if (checkedCodeSet.contains(mgpCodeMst.getValue1())) {
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

        LogService.info(AuthEmpCodeListController.OWN_TITLE, this.getClass().getSimpleName(), "雇用区分情報検索処理", "正常終了");
    	return result;
    }
}
