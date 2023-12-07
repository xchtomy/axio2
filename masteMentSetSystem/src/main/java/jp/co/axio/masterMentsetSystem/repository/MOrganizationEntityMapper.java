package jp.co.axio.masterMentsetSystem.repository;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import jp.co.axio.masterMentsetSystem.model.MOrganizationEntity;
import jp.co.axio.masterMentsetSystem.model.MOrganizationEntityExample;
import jp.co.axio.masterMentsetSystem.model.MOrganizationEntityKey;

@Mapper
public interface MOrganizationEntityMapper {
    long countByExample(MOrganizationEntityExample example);

    int deleteByExample(MOrganizationEntityExample example);

    int deleteByPrimaryKey(MOrganizationEntityKey key);

    int insert(MOrganizationEntity record);

    int insertSelective(MOrganizationEntity record);

    List<MOrganizationEntity> selectByExample(MOrganizationEntityExample example);

    MOrganizationEntity selectByPrimaryKey(MOrganizationEntityKey key);

    int updateByExampleSelective(@Param("record") MOrganizationEntity record, @Param("example") MOrganizationEntityExample example);

    int updateByExample(@Param("record") MOrganizationEntity record, @Param("example") MOrganizationEntityExample example);

    int updateByPrimaryKeySelective(MOrganizationEntity record);

    int updateByPrimaryKey(MOrganizationEntity record);


	List<MOrganizationEntity> selectMOrganizationByAuthOrgCodeList(
																 @Param("codeMapList") List<Map<String, String>> codeMapList
																,@Param("searchFlag") boolean searchFlag
																,@Param("searchCompanyCode") String searchCompanyCode
																,@Param("searchDepartmentCode") String searchDepartmentCode
																,@Param("searchDepartmentName") String searchDepartmentName
																,@Param("searchStartDateYmd") String searchStartDateYmd
																,@Param("searchEndDateYmd") String searchEndDateYmd
																);
}