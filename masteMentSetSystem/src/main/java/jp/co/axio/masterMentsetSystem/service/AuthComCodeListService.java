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
import jp.co.axio.masterMentsetSystem.controller.AuthComCodeListController;
import jp.co.axio.masterMentsetSystem.dto.AuthComCodeListDto;
import jp.co.axio.masterMentsetSystem.model.MgpCodeMst;
import jp.co.axio.masterMentsetSystem.repository.MgpCodeMstSelectMapper;

/**
 * 会社コード一覧画面サービスクラス
 *
 * @author axio
 * @version 1.0
 */
@Service
public class AuthComCodeListService {

    /* 汎用コードマスタ */
    @Autowired
    MgpCodeMstSelectMapper MgpCodeMstSelectMapper;

    /**
     * 会社情報検索処理
     *
     * @param selectedCodeMapList - 選択済みコードのマップリスト（List<Map<String,String>>）
     * @param checkedCodeMapList - チェックコードのマップリスト（List<Map<String,String>>）
     * @param searchFlag - true:検索条件の検索をする／false:検索条件の検索をしない（選択済みの会社のみ）（boolean）
     * @param searchCompanyCode - 検索する会社コード（String）
     * @param searchCompanyName - 検索する会社名（String）
     * @return 会社情報リスト（List<AuthComCodeListDto>）
     */
    @Transactional
    public List<AuthComCodeListDto> selectMgpCodeMst (List<Map<String,String>> selectedCodeMapList
    													, List<Map<String,String>> checkedCodeMapList
    													, boolean searchFlag
    													, String searchCompanyCode
    													, String searchCompanyName) {
		List<AuthComCodeListDto> result = new ArrayList<AuthComCodeListDto>();
        LogService.info(AuthComCodeListController.OWN_TITLE, this.getClass().getSimpleName(), "会社情報検索処理", "開始");

        List<MgpCodeMst> mgpCodeMstList = null;
        if (selectedCodeMapList == null) selectedCodeMapList = new ArrayList<Map<String, String>>();
        if (checkedCodeMapList == null) checkedCodeMapList = new ArrayList<Map<String, String>>();
        if (searchCompanyCode == null) searchCompanyCode = "";
        if (searchCompanyName == null) searchCompanyName = "";

        Set<String> selectedCodeSet = new HashSet<String>();
		Set<String> checkedCodeSet = new HashSet<String>();
        Set<String> codeSet = new HashSet<String>();
        for (Map<String, String> map:selectedCodeMapList) {
        	if (map != null && map.containsKey(AuthComCodeListController.CALL_PARAMETER_DATA_KEY)) {
        		String val = map.get(AuthComCodeListController.CALL_PARAMETER_DATA_KEY);
        		selectedCodeSet.add(val);
        	}
        }
        for (Map<String, String> map:checkedCodeMapList) {
        	if (map != null && map.containsKey(AuthComCodeListController.CALL_PARAMETER_DATA_KEY)) {
        		String val = map.get(AuthComCodeListController.CALL_PARAMETER_DATA_KEY);
        		checkedCodeSet.add(val);
        	}
        }
        codeSet.addAll(selectedCodeSet);
        //codeSet.addAll(checkedCodeSet);

        if (searchFlag || codeSet.size() > 0) {
			// 「\」「%」をエスケープ
			if (searchCompanyCode.indexOf("\\") >= 0) searchCompanyCode = searchCompanyCode.replace("\\", "\\\\");
			if (searchCompanyCode.indexOf("%") >= 0) searchCompanyCode = searchCompanyCode.replace("%", "\\%");
			if (searchCompanyName.indexOf("\\") >= 0) searchCompanyName = searchCompanyName.replace("\\", "\\\\");
			if (searchCompanyName.indexOf("%") >= 0) searchCompanyName = searchCompanyName.replace("%", "\\%");
			mgpCodeMstList = MgpCodeMstSelectMapper.selectMgpCodeMstByAuthComCodeList(codeSet
																						, searchFlag
																						, searchCompanyCode
																						, searchCompanyName);
        }
		if (mgpCodeMstList != null) {
			List<AuthComCodeListDto> list = new ArrayList<AuthComCodeListDto>();
			for (MgpCodeMst mgpCodeMst : mgpCodeMstList) {
				AuthComCodeListDto dto = new AuthComCodeListDto();
				dto.setCompanyCode(mgpCodeMst.getValue1());
				dto.setCompanyName(mgpCodeMst.getValue2());
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

        LogService.info(AuthComCodeListController.OWN_TITLE, this.getClass().getSimpleName(), "会社情報検索処理", "正常終了");
    	return result;
    }
}
