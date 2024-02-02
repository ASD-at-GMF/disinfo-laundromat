<script lang="ts">
	import TabsRoot from '$components/TabsRoot.svelte';
	import TabsList from '$components/TabsList.svelte';
	import TabsTrigger from '$components/TabsTrigger.svelte';
	import TabsContent from '$components/TabsContent.svelte';
	import DropdownSelect from '$components/DropdownSelect.svelte';
	import { Label, Select } from 'bits-ui';
	import type { LabeledValue } from '$types';

	const dropdown_dummy_region: LabeledValue[] = [
		{ label: 'US', value: 'US' },
		{ label: 'EU', value: 'EU' }
	];

	const dropdown_dummy_language: LabeledValue[] = [
		{ label: 'english', value: 'english' },
		{ label: 'dutch', value: 'dutch' }
	];

	interface InputData {
		region: LabeledValue,
		language: LabeledValue,
		[index: string]: LabeledValue;
	}

	let inputData : InputData = {
		region: '',
		language: '',
	};

	function handleSelectedChanged({value, kind} {value: LabeledValue, kind: string}) {
		if (inputData.hasOwnProperty(value.label)) {
			inputData[value.label] = value.value;
			console.log(inputData);
		} else {
			console.log(`Unknown property: ${value.label}`);
		}
	}
</script>

<main class="w-100">
	<section class="grid grid-rows-2 gap-4">
		<div class=" grid grid-cols-1 gap-4 md:grid-cols-2">
			<div class="bg-blue-300">Explanation</div>
			<div class="">
				<TabsRoot value="content similarity">
					<TabsList>
						<TabsTrigger value="content similarity">Content similarity</TabsTrigger>
						<TabsTrigger value="metadata similarity">Metadata similarity</TabsTrigger>
					</TabsList>
					<TabsContent value="content similarity">
						<p>
							Search for similar content shared across the internet. Laundromat uses popular search
							engines to find related websites. Discover networks of malicious actors/websites
							collectively sharing disinformation.
						</p>
						<form>
							<Label.Root for="browsers">browsers</Label.Root>
							<DropdownSelect
								id="region_selector"
								name="region"
								kind="region"
								selected={dropdown_dummy_region[0]}
								items={dropdown_dummy_region}
								onSelectedChange={handleSelectedChanged}
							/>
							<DropdownSelect
								id="language_selector"
								name="language"
								kind="lagnuage"
								selected={dropdown_dummy_language[0]}
								items={dropdown_dummy_language}
								onSelectedChange={handleSelectedChanged}
							/>
							<button type="submit">Submit</button>
							<form></form>
						</form></TabsContent
					>
					<TabsContent value="metadata similarity">test 2 test 2</TabsContent>
				</TabsRoot>
			</div>
		</div>
		<div>
			<Label.Root for="use case list" class="bg-green-300">Label!</Label.Root>
			<ul id="use case list" class="grid grid-cols-1 gap-x-4 md:grid-cols-3">
				<li class="bg-pink-500">test1</li>
				<li class="bg-pink-500">test2</li>
				<li class="bg-pink-500">test3</li>
			</ul>
		</div>
	</section>
</main>
