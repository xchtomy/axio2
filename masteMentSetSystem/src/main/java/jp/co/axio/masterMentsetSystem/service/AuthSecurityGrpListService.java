package jp.co.axio.masterMentsetSystem.service;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.logging.java.SimpleFormatter;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jp.co.axio.masterMentsetSystem.controller.AuthSecurityGrpListForm;
import jp.co.axio.masterMentsetSystem.dto.AuthSecurityGrpListDto;
import jp.co.axio.masterMentsetSystem.model.MOrganizationAdGroupEntity;
import jp.co.axio.masterMentsetSystem.repository.MOrganizationAdGroupMapper;

@Service
public class AuthSecurityGrpListService {

    @Autowired
    MOrganizationAdGroupMapper mOrganizationAdGroupMapper;

    SimpleDateFormat slashrFormat = new SimpleDateFormat("yyyy/MM/dd");
    SimpleDateFormat hyphenFormat = new SimpleDateFormat("yyyy-MM-dd");

    /**
     * セキュリティグループ検索
     * @param form
     * @return
     * @throws ParseException
     */
    @Transactional
    public List<AuthSecurityGrpListDto> selectGroupList(AuthSecurityGrpListForm form) throws ParseException {
        
        List<AuthSecurityGrpListDto> groupList = new ArrayList<>();
        MOrganizationAdGroupEntity entity = new MOrganizationAdGroupEntity();

        entity.setSecurityGroupCode(form.getDailogSecurityGroupCode());
        entity.setGroupName(form.getDailogGroupName());
        entity.setNote(form.getDailogGroupNote());
        entity.setStartDate(slashrFormat.parse(form.getDailogStartDate()));

        groupList = mOrganizationAdGroupMapper.selectGroupList(entity);

        // 開始日、終了日フォーマット変換
        for (int i = 0; i < groupList.size(); i++) {
            groupList.get(i).setStartDate(convertDateFormat(hyphenFormat, slashrFormat, groupList.get(i).getStartDate()));
            groupList.get(i).setEndDate(convertDateFormat(hyphenFormat, slashrFormat, groupList.get(i).getEndDate()));
        }
        

        return groupList;
    }

    /**
     * 日付変換
     * @param beforeFormat
     * @param afterFormat
     * @param date
     * @return
     * @throws ParseException
     */
    public String convertDateFormat(SimpleDateFormat beforeFormat, SimpleDateFormat afterFormat, String date) throws ParseException {
        
        return afterFormat.format(beforeFormat.parse(date));

    }





}
