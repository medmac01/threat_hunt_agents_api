# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import json
import subprocess
import traceback
from .exceptions import UnavailableGalaxyResourcesError
from abc import ABCMeta
from collections import defaultdict
from pathlib import Path
from pymisp import AbstractMISP, MISPEvent, MISPObject
from stix2.v20.sdo import Indicator as Indicator_v20
from stix2.v21.sdo import Indicator as Indicator_v21
from types import GeneratorType
from typing import Optional, Union
from uuid import UUID, uuid5

_INDICATOR_TYPING = Union[
    Indicator_v20,
    Indicator_v21
]
_DATA_PATH = Path(__file__).parents[1].resolve() / 'data'

_VALID_DISTRIBUTIONS = (0, 1, 2, 3, 4)
_RFC_VERSIONS = (1, 3, 4, 5)
_UUIDv4 = UUID('76beed5f-7251-457e-8c2a-b45f7b589d3d')


class STIXtoMISPParser(metaclass=ABCMeta):
    def __init__(self, distribution: int, sharing_group_id: Union[int, None],
                 galaxies_as_tags: bool):
        self._identifier: str
        self.__relationship_types: dict

        self._clusters: dict = {}
        self.__errors: defaultdict = defaultdict(set)
        self.__warnings: defaultdict = defaultdict(set)
        self.__distribution = self._sanitise_distribution(distribution)
        self.__sharing_group_id = self._sanitise_sharing_group_id(
            sharing_group_id
        )
        self.__galaxies_as_tags = self._sanitise_galaxies_as_tags(
            galaxies_as_tags
        )
        if self.galaxies_as_tags:
            self.__galaxy_feature = 'as_tag_names'
            self.__synonyms_path = _DATA_PATH / 'synonymsToTagNames.json'
        else:
            self._galaxies: dict = {}
            self.__galaxy_feature = 'as_container'
        self.__replacement_uuids: dict = {}

    def _sanitise_distribution(self, distribution: int) -> int:
        try:
            sanitised = int(distribution)
        except (TypeError, ValueError) as error:
            self._distribution_error(error)
            return 0
        if sanitised in _VALID_DISTRIBUTIONS:
            return sanitised
        self._distribution_value_error(sanitised)
        return 0

    def _sanitise_galaxies_as_tags(self, galaxies_as_tags: bool):
        if isinstance(galaxies_as_tags, bool):
            return galaxies_as_tags
        if galaxies_as_tags in ('true', 'True', '1', 1):
            return True
        if galaxies_as_tags in ('false', 'False', '0', 0):
            return False
        self._galaxies_as_tags_error(galaxies_as_tags)
        return False

    def _sanitise_sharing_group_id(
            self, sharing_group_id: Union[int, None]) -> Union[int, None]:
        if sharing_group_id is None:
            return None
        try:
            return int(sharing_group_id)
        except (TypeError, ValueError) as error:
            self._sharing_group_id_error(error)
            return None

    ############################################################################
    #                                PROPERTIES                                #
    ############################################################################

    @property
    def distribution(self) -> int:
        return self.__distribution

    @property
    def errors(self) -> dict:
        return self.__errors

    @property
    def galaxies_as_tags(self) -> bool:
        return self.__galaxies_as_tags

    @property
    def galaxy_feature(self) -> bool:
        return self.__galaxy_feature

    @property
    def relationship_types(self) -> dict:
        try:
            return self.__relationship_types
        except AttributeError:
            self.__get_relationship_types()
            return self.__relationship_types

    @property
    def replacement_uuids(self) -> dict:
        return self.__replacement_uuids

    @property
    def sharing_group_id(self) -> Union[int, None]:
        return self.__sharing_group_id

    @property
    def synonyms_mapping(self) -> dict:
        try:
            return self.__synonyms_mapping
        except AttributeError:
            self.__get_synonyms_mapping()
            return self.__synonyms_mapping

    @property
    def synonyms_path(self) -> Path:
        return self.__synonyms_path

    @property
    def warnings(self) -> defaultdict:
        return self.__warnings

    ############################################################################
    #                   ERRORS AND WARNINGS HANDLING METHODS                   #
    ############################################################################

    def _attack_pattern_error(
            self, attack_pattern_id: str, exception: Exception):
        tb = self._parse_traceback(exception)
        self.__errors[self._identifier].add(
            'Error parsing the Attack Pattern object with id '
            f'{attack_pattern_id}: {tb}'
        )

    def _attribute_from_pattern_parsing_error(self, indicator_id: str):
        self.__errors[self._identifier].add(
            f'Error while parsing pattern from indicator with id {indicator_id}'
        )

    def _course_of_action_error(
            self, course_of_action_id: str, exception: Exception):
        self.__errors[self._identifier].add(
            'Error parsing the Course of Action object with id'
            f'{course_of_action_id}: {self._parse_traceback(exception)}'
        )

    def _critical_error(self, exception: Exception):
        self.__errors[self._identifier].add(
            f'The Following exception was raised: {exception}'
        )

    def _distribution_error(self, exception: Exception):
        self.__errors['init'].add(
            f'Wrong distribution format: {exception}'
        )

    def _distribution_value_error(self, distribution: int):
        self.__errors['init'].add(
            f'Invalid distribution value: {distribution}'
        )

    def _galaxies_as_tags_error(self, galaxies_as_tags):
        self.__errors['init'].add(
            f'Invalid galaxies_as_tags flag: {galaxies_as_tags} (bool expected)'
        )

    def _hash_type_error(self, hash_type: str):
        self.__errors[self._identifier].add(f'Wrong hash type: {hash_type}')

    def _identity_error(self, identity_id: str, exception: Exception):
        tb = self._parse_traceback(exception)
        self.__errors[self._identifier].add(
            f'Error parsing the Identity object with id {identity_id}: {tb}'
        )

    def _indicator_error(self, indicator_id: str, exception: Exception):
        tb = self._parse_traceback(exception)
        self.__errors[self._identifier].add(
            f'Error parsing the Indicator object with id {indicator_id}: {tb}'
        )

    def _intrusion_set_error(self, intrusion_set_id: str, exception: Exception):
        self.__errors[self._identifier].add(
            f'Error parsing the Intrusion Set object with id {intrusion_set_id}'
            f': {self._parse_traceback(exception)}'
        )

    def _location_error(self, location_id: str, exception: Exception):
        tb = self._parse_traceback(exception)
        self.__errors[self._identifier].add(
            f'Error parsing the Location object with id {location_id}: {tb}'
        )

    def _malware_error(self, malware_id: str, exception: Exception):
        tb = self._parse_traceback(exception)
        self.__errors[self._identifier].add(
            f'Error parsing the Malware object with id {malware_id}: {tb}'
        )

    def _no_converted_content_from_pattern_warning(
            self, indicator: _INDICATOR_TYPING):
        self.__warnings[self._identifier].add(
            "No content to extract from the following Indicator's (id: "
            f'{indicator.id}) pattern: {indicator.pattern}'
        )

    def _object_ref_loading_error(self, object_ref: str):
        self.__errors[self._identifier].add(
            f'Error loading the STIX object with id {object_ref}'
        )

    def _object_type_loading_error(self, object_type: str):
        self.__errors[self._identifier].add(
            f'Error loading the STIX object of type {object_type}'
        )

    def _observable_mapping_error(
            self, observed_data_id: str, observable_types: str):
        self.__errors[self._identifier].add(
            'Unable to map observable objects related to the Observed Data '
            f'object with id {observed_data_id} containing the folowing types'
            f": {observable_types.__str__().replace('_', ', ')}"
        )

    def _observable_object_error(self, observable_id: str, exception: Exception):
        self.__errors[self._identifier].add(
            f'Error parsing the Observable object with id {observable_id}'
            f': {self._parse_traceback(exception)}'
        )

    def _observable_object_mapping_error(self, observable_id: str):
        self.__errors[self._identifier].add(
            f'Unable to map observable object with id {observable_id}.'
        )

    def _observed_data_error(self, observed_data_id: str, exception: Exception):
        self.__errors[self._identifier].add(
            f'Error parsing the Observed Data object with id {observed_data_id}'
            f': {self._parse_traceback(exception)}'
        )

    @staticmethod
    def _parse_traceback(exception: Exception) -> str:
        tb = ''.join(traceback.format_tb(exception.__traceback__))
        return f'{tb}{exception.__str__()}'

    def _sharing_group_id_error(self, exception: Exception):
        self.__errors['init'].add(
            f'Wrong sharing group id format: {exception}'
        )

    def _threat_actor_error(self, threat_actor_id: str, exception: Exception):
        self.__errors[self._identifier].add(
            f'Error parsing the Threat Actor object with id {threat_actor_id}'
            f': {self._parse_traceback(exception)}'
        )

    def _tool_error(self, tool_id: str, exception: Exception):
        tb = self._parse_traceback(exception)
        self.__errors[self._identifier].add(
            f'Error parsing the Tool object with id {tool_id}: {tb}'
        )

    def _unable_to_load_stix_object_type_error(self, object_type: str):
        self.__errors[self._identifier].add(
            f'Unable to load STIX object type: {object_type}'
        )

    def _undefined_object_error(self, object_id: str):
        self.__errors[self._identifier].add(
            f'Unable to define the object identified with the id: {object_id}'
        )

    def _unknown_attribute_type_warning(self, attribute_type: str):
        self.__warnings[self._identifier].add(
            f'MISP attribute type not mapped: {attribute_type}'
        )

    def _unknown_marking_object_warning(self, marking_ref: str):
        self.__warnings[self._identifier].add(
            f'Unknown marking definition object referenced by id {marking_ref}'
        )

    def _unknown_marking_ref_warning(self, marking_ref: str):
        self.__warnings[self._identifier].add(
            f'Unknown marking ref: {marking_ref}'
        )

    def _unknown_network_protocol_warning(
            self, protocol: str, indicator_id: str):
        self.__warnings[self._identifier].add(
            f'Unknown network protocol: {protocol} in the patterning '
            f'expression describing the Indicator with id {indicator_id}'
        )

    def _unknown_object_name_warning(self, name: str):
        self.__warnings[self._identifier].add(
            f'MISP object name not mapped: {name}'
        )

    def _unknown_parsing_function_error(self, feature: str):
        self.__errors[self._identifier].add(
            f'Unknown STIX parsing function name: {feature}'
        )

    def _unknown_pattern_mapping_warning(
            self, indicator_id: str, pattern_types: Union[GeneratorType, str]):
        if not isinstance(pattern_types, GeneratorType):
            pattern_types = pattern_types.split('_')
        self.__warnings[self._identifier].add(
            f'Unable to map pattern from the Indicator with id {indicator_id}, '
            f"containing the following types: {', '.join(pattern_types)}"
        )

    def _unknown_pattern_type_error(self, indicator_id: str, pattern_type: str):
        self.__errors[self._identifier].add(
            f'Unknown pattern type in indicator with id {indicator_id}'
            f': {pattern_type}'
        )

    def _unknown_stix_object_type_error(self, object_type: str):
        self.__errors[self._identifier].add(
            f'Unknown STIX object type: {object_type}'
        )

    def _unmapped_pattern_warning(self, indicator_id: str, feature: str):
        self.__warnings[self._identifier].add(
            f'Unmapped pattern part in indicator with id {indicator_id}'
            f': {feature}'
        )

    def _vulnerability_error(self, vulnerability_id: str, exception: Exception):
        self.__errors[self._identifier].add(
            f'Error parsing the Vulnerability object with id {vulnerability_id}'
            f': {self._parse_traceback(exception)}'
        )

    ############################################################################
    #            MISP OBJECT RELATIONSHIPS MAPPING CREATION METHODS            #
    ############################################################################

    def __get_relationship_types(self):
        relationships_path = Path(
            AbstractMISP().resources_path / 'misp-objects' / 'relationships'
        )
        with open(relationships_path / 'definition.json', 'r') as f:
            relationships = json.load(f)
        self.__relationship_types = {
            relationship['name']: relationship['opposite'] for relationship
            in relationships['values'] if 'opposite' in relationship
        }

    ############################################################################
    #          SYNONYMS TO GALAXY TAG NAMES MAPPING HANDLING METHODS.          #
    ############################################################################

    def __galaxies_up_to_date(self) -> bool:
        fingerprint_path = _DATA_PATH / 'synonymsToTagNames.fingerprint'
        if not fingerprint_path.exists():
            return False
        latest_fingerprint = self.__get_misp_galaxy_fingerprint()
        if latest_fingerprint is None:
            return False
        with open(fingerprint_path, 'rt', encoding='utf-8') as f:
            fingerprint = f.read()
        return fingerprint == latest_fingerprint

    @staticmethod
    def __get_misp_galaxy_fingerprint():
        galaxy_path = _DATA_PATH / 'misp-galaxy'
        status = subprocess.Popen(
            [
                'git',
                'submodule',
                'status',
                galaxy_path
            ],
            stdout=subprocess.PIPE
        )
        stdout = status.communicate()[0]
        try:
            return stdout.decode().split(' ')[1]
        except IndexError:
            return None

    def __get_synonyms_mapping(self):
        if not self.synonyms_path.exists() or not self.__galaxies_up_to_date():
            data_path = _DATA_PATH / 'misp-galaxy' / 'clusters'
            if not data_path.exists():
                raise UnavailableGalaxyResourcesError(data_path)
            synonyms_mapping = defaultdict(list)
            for filename in data_path.glob('*.json'):
                with open(filename, 'rt', encoding='utf-8') as f:
                    cluster_definition = json.loads(f.read())
                cluster_type = f"misp-galaxy:{cluster_definition['type']}"
                for cluster in cluster_definition['values']:
                    value = cluster['value']
                    tag_name = f'{cluster_type}="{value}"'
                    synonyms_mapping[value].append(tag_name)
                    if cluster.get('meta', {}).get('synonyms') is not None:
                        for synonym in cluster['meta']['synonyms']:
                            synonyms_mapping[synonym].append(tag_name)
            with open(self.synonyms_path, 'wt', encoding='utf-8') as f:
                f.write(json.dumps(synonyms_mapping))
            latest_fingerprint = self.__get_misp_galaxy_fingerprint()
            if latest_fingerprint is not None:
                fingerprint_path = _DATA_PATH / 'synonymsToTagNames.fingerprint'
                with open(fingerprint_path, 'wt', encoding='utf-8') as f:
                    f.write(latest_fingerprint)
        with open(self.synonyms_path, 'rt', encoding='utf-8') as f:
            self.__synonyms_mapping = json.loads(f.read())

    ############################################################################
    #                     UUID SANITATION HANDLING METHODS                     #
    ############################################################################

    def _check_uuid(self, object_id: str):
        object_uuid = self._extract_uuid(object_id)
        if UUID(object_uuid).version not in _RFC_VERSIONS and object_uuid not in self.replacement_uuids:
            self.replacement_uuids[object_uuid] = self._create_v5_uuid(
                object_uuid
            )

    @staticmethod
    def _create_v5_uuid(value: str) -> UUID:
        return uuid5(_UUIDv4, value)

    def _sanitise_attribute_uuid(
            self, object_id: str, comment: Optional[str] = None) -> dict:
        attribute_uuid = self._extract_uuid(object_id)
        attribute_comment = f'Original UUID was: {attribute_uuid}'
        if attribute_uuid in self.replacement_uuids:
            return {
                'uuid': self.replacement_uuids[attribute_uuid],
                'comment': f'{comment} - {attribute_comment}' if comment else attribute_comment
            }
        if UUID(attribute_uuid).version not in _RFC_VERSIONS:
            sanitised_uuid = self._create_v5_uuid(attribute_uuid)
            self.replacement_uuids[attribute_uuid] = sanitised_uuid
            return {
                'uuid': sanitised_uuid,
                'comment': f'{comment} - {attribute_comment}' if comment else attribute_comment
            }
        return {'uuid': attribute_uuid}

    def _sanitise_object_uuid(
            self, misp_object: Union[MISPEvent, MISPObject], object_id: str):
        object_uuid = self._extract_uuid(object_id)
        if object_uuid in self.replacement_uuids:
            comment = f'Original UUID was: {object_uuid}'
            misp_object.comment = f'{misp_object.comment} - {comment}' if hasattr(misp_object, 'comment') else comment
            object_uuid = self.replacement_uuids[object_uuid]
        misp_object.uuid = object_uuid

    def _sanitise_uuid(self, object_id: str) -> str:
        object_uuid = self._extract_uuid(object_id)
        if UUID(object_uuid).version not in _RFC_VERSIONS:
            if object_uuid in self.replacement_uuids:
                return self.replacement_uuids[object_uuid]
            sanitised_uuid = self._create_v5_uuid(object_uuid)
            self.replacement_uuids[object_uuid] = sanitised_uuid
            return sanitised_uuid
        return object_uuid