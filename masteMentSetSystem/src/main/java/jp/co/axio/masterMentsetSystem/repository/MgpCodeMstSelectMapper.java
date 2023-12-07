package jp.co.axio.masterMentsetSystem.repository;

import java.util.List;
import java.util.Set;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import jp.co.axio.masterMentsetSystem.model.MgpCodeMst;

@Mapper
public interface MgpCodeMstSelectMapper {

    List<MgpCodeMst> selectMgpCodeMstSearchByclassCode();
    
    
    List<MgpCodeMst> selectMgpCodeMstSearchByGpuMasterSet(@Param("classCodeId") String classCodeId);


	List<MgpCodeMst> selectMgpCodeMstByAuthComCodeList(
														 @Param("companyCodeSet") Set<String> companyCodeSet
														,@Param("searchFlag") boolean searchFlag
														,@Param("searchCompanyCode") String searchCompanyCode
														,@Param("searchCompanyName") String searchCompanyName
														);
	List<MgpCodeMst> selectMgpCodeMstByAuthEmpCodeList(
														 @Param("employmentCodeSet") Set<String> employmentCodeSet
														,@Param("searchFlag") boolean searchFlag
														,@Param("searchEmploymentCode") String searchEmploymentCode
														,@Param("searchEmploymentName") String searchEmploymentName
														);
}