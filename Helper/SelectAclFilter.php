<?php
namespace MrGreenStuff\Bundle\AclSonataAdminExtensionBundle\Helper;

use Symfony\Component\Security\Acl\Permission\MaskBuilder;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;

class SelectAclFilter
{
/*ACL SELECT FILTERING*/
	public function updateQueryAcl($query,$admin,$isTheMaster=false){
		$user = $admin->container->get('security.context')->getToken()->getUser();
        $securityIdentity = UserSecurityIdentity::fromAccount($user);

        // Get identity ACL identifier
        $identifier = sprintf('%s-%s', $securityIdentity->getClass(), $securityIdentity->getUsername());

        $identityStmt = $admin->databaseConnection->prepare('SELECT id FROM acl_security_identities WHERE identifier = :identifier');
        $identityStmt->bindValue('identifier', $identifier);
        $identityStmt->execute();

        $identityId = $identityStmt->fetchColumn();

        // Get class ACL identifier
        $classType = $admin->getClass();
        $classStmt = $admin->databaseConnection->prepare('SELECT id FROM acl_classes WHERE class_type = :classType');
        $classStmt->bindValue('classType', $classType);
        $classStmt->execute();
        $classId = $classStmt->fetchColumn();
        if ($identityId) {
            $ids = array();
			if($classId){
				$entriesStmt = $admin->databaseConnection->prepare('SELECT object_identifier FROM acl_entries AS ae JOIN acl_object_identities AS aoi ON ae.object_identity_id = aoi.id WHERE ae.class_id = :classId AND ae.security_identity_id = :identityId AND (:view = ae.mask & :view OR :operator = ae.mask & :operator OR :master = ae.mask & :master OR :owner = ae.mask & :owner)');
				$entriesStmt->bindValue('classId', $classId);
				$entriesStmt->bindValue('identityId', $identityId);
				$entriesStmt->bindValue('view', MaskBuilder::MASK_VIEW);
				$entriesStmt->bindValue('operator', MaskBuilder::MASK_OPERATOR);
				$entriesStmt->bindValue('master', MaskBuilder::MASK_MASTER);
				$entriesStmt->bindValue('owner', MaskBuilder::MASK_OWNER);
				$entriesStmt->execute();
				foreach ($entriesStmt->fetchAll() as $row) {
					$ids[] = $row['object_identifier'];
				}
			}
			if (method_exists($admin,'getMasterAclClass') && method_exists($admin,'getMasterAclPath')) {
				$classStmt = $admin->databaseConnection->prepare('SELECT id FROM acl_classes WHERE class_type = :classType');
				$classStmt->bindValue('classType', $admin->getMasterAclClass());
				$classStmt->execute();

				$classId = $classStmt->fetchColumn();
				$entriesStmt = $admin->databaseConnection->prepare('SELECT object_identifier FROM acl_entries AS ae JOIN acl_object_identities AS aoi ON ae.object_identity_id = aoi.id WHERE ae.class_id = :classId AND ae.security_identity_id = :identityId AND (:view = ae.mask & :view OR :operator = ae.mask & :operator OR :master = ae.mask & :master OR :owner = ae.mask & :owner)');
				$entriesStmt->bindValue('classId', $classId);
				$entriesStmt->bindValue('identityId', $identityId);
				$entriesStmt->bindValue('view', MaskBuilder::MASK_VIEW);
				$entriesStmt->bindValue('operator', MaskBuilder::MASK_OPERATOR);
				$entriesStmt->bindValue('master', MaskBuilder::MASK_MASTER);
				$entriesStmt->bindValue('owner', MaskBuilder::MASK_OWNER);
				$entriesStmt->execute();
				//ARRAY OF idsMaster
				$idsMaster = array();
				foreach ($entriesStmt->fetchAll() as $row) {
						$idsMaster[] = $row['object_identifier'];
				}
				$parents=$admin->getMasterAclPath();
				//HERE UPDATE THE QUERY
				if(!$isTheMaster){
					foreach($parents as $key=>$parent){
							//FIRST shorcut is 'o'
							if($key==0){
									$query->leftJoin('o.'.$parent[0],$parent[1]);
							}else{
							//Shortcut is precedent shortcut
									$query->leftJoin($parents[$key-1][1].'.'.$parent[0],$parent[1]);
							}
							//HERE WE ARE AFTER THE LEFT JOIN ON MASTER ACL CLASS WE PASS idsMaster array param
							if(($key+1)==count($parents)){
									//HERE FOR OBJECT CREATED BY CURRENT USER AND WITH STRICT MODE IS OF
									if(count($ids) && method_exists($admin,'getMasterAclStrict') && !$admin->getMasterAclStrict()){
											//OR EXPRESSION WITH PARENTHESIS
											$orCondition = $query->expr()->orx();
											$orCondition->add($query->expr()->in('o.id', ':ids'));
											$orCondition->add($query->expr()->in($parent[1].'.id',':idsMaster'));
											$query->andWhere($orCondition)->setParameter('ids', $ids)->setParameter('idsMaster', $idsMaster);
									}else{
											$query->andWhere($parent[1].'.id IN (:idsMaster'.$key.')')->setParameter('idsMaster'.$key, $idsMaster);
									}
							}
					}
				}else{
					$query->andWhere('o.id IN (:idsMaster)')->setParameter('idsMaster', $idsMaster);
				}
				return;
			}elseif(count($ids)){
				//NORMAL BEHAVIOR
				$query
					->andWhere('o.id IN (:ids)')
					->setParameter('ids', $ids)
				;
				return;
			}
		}
	}